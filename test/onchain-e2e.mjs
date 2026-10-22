// On-chain end-to-end test against the upstream `examples/confidential`
// contracts — the only test where the Rust UltraHonk verifier, not bb.js,
// judges the SDK's proofs. It deploys fresh verifier + auditor registries and
// the factory, has the factory deploy an allowlist + compliant token, registers
// the committed VKs, and runs register → deposit → merge → transfer → withdraw
// → transfer back → freeze → clawback ×2 with real proofs, checking after
// every step that the SDK's openings re-commit to the on-chain points (via
// StateEngine.sync's consistency check) and that the emitted events decode to
// exactly what was submitted. Along the way it exercises the factory and admin
// helpers (roles, freeze, allowlist, compliance config).
//
// Env-gated (needs a network and the example wasms), SKIPS cleanly when unset:
//
//   # build stellar-contracts v0.8.0 examples/confidential/* to wasm, e.g.
//   #   stellar contract build --package confidential-verifier-example --out-dir <dir>
//   #   (likewise -auditor-, -compliant-token-, -allowlist-policy-, -factory-example)
//   # and start a local network (testnet limits keep the cost check honest):
//   #   docker run -d --rm -p 8011:8000 stellar/quickstart:latest --local --enable rpc --limits testnet
//   CTD_E2E_RPC_URL=http://localhost:8011/rpc \
//   CTD_E2E_FRIENDBOT_URL=http://localhost:8011/friendbot \
//   CTD_E2E_WASM_DIR=<dir> \
//   tsx test/onchain-e2e.mjs
//
// Every account is fresh and friendbot-funded; the underlying asset is the
// native XLM SAC (no trustlines or minting needed).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  Address,
  Asset,
  Keypair,
  Operation,
  TransactionBuilder,
  BASE_FEE,
  rpc,
  xdr,
} from "@stellar/stellar-sdk";

import {
  CIRCUIT_TYPE,
  ChainClient,
  CircuitProver,
  H,
  MANAGER_ROLE,
  MemoryStore,
  StateEngine,
  TOKEN_ROLES,
  addressToField,
  allowUser,
  auditTransfer,
  auditWithdraw,
  buildRegisterWitness,
  buildTransferWitness,
  buildWithdrawWitness,
  clawback,
  clawbackNonce,
  commit,
  deployAllowlistAndToken,
  deriveKeys,
  disallowUser,
  fetchEvents,
  fieldIn,
  freezeAccount,
  grantRole,
  hasRole,
  humanizeContractError,
  isAllowed,
  isFrozen,
  keypairSigner,
  parseContractErrorCode,
  pointIn,
  pointToBytes,
  predictTokenAddress,
  randomScalar,
  readAdmin,
  readComplianceConfig,
  scalarMul,
  setComplianceConfig,
  submitDeposit,
  submitMerge,
  submitRegister,
  submitTransfer,
  submitWithdraw,
  unfreezeAccount,
} from "../src/index.ts";
import { loadCircuit } from "../src/proving/artifacts.ts";

const RPC_URL = process.env.CTD_E2E_RPC_URL;
const WASM_DIR = process.env.CTD_E2E_WASM_DIR;
if (!RPC_URL || !WASM_DIR) {
  console.log("onchain-e2e: SKIPPED (set CTD_E2E_RPC_URL and CTD_E2E_WASM_DIR to run)");
  process.exit(0);
}

let pass = 0,
  fail = 0;
function check(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.error(`  ✗ ${name}${detail ? `\n      ${detail}` : ""}`);
  }
}

const server = new rpc.Server(RPC_URL, { allowHttp: RPC_URL.startsWith("http://") });
const network = await server.getNetwork();
const PASSPHRASE = process.env.CTD_E2E_PASSPHRASE ?? network.passphrase;
const FRIENDBOT = process.env.CTD_E2E_FRIENDBOT_URL ?? network.friendbotUrl;
console.log(`onchain-e2e: ${RPC_URL} (protocol ${network.protocolVersion})\n`);

const wasm = (name) => readFileSync(join(WASM_DIR, `confidential_${name}_example.wasm`));
const addr = (a) => new Address(a).toScVal();

async function fund(kp) {
  const r = await fetch(`${FRIENDBOT}?addr=${kp.publicKey()}`);
  if (!r.ok) throw new Error(`friendbot ${r.status}: ${(await r.text()).slice(0, 200)}`);
}

/** Submit one non-invoke-contract operation (upload / create) as `kp`. */
async function submitOp(kp, op) {
  const source = await server.getAccount(kp.publicKey());
  const tx = new TransactionBuilder(source, { fee: BASE_FEE, networkPassphrase: PASSPHRASE })
    .addOperation(op)
    .setTimeout(180)
    .build();
  const prepared = await server.prepareTransaction(tx);
  prepared.sign(kp);
  const sent = await server.sendTransaction(prepared);
  if (sent.status === "ERROR") throw new Error(`send rejected: ${JSON.stringify(sent.errorResult)}`);
  const res = await server.pollTransaction(sent.hash, { attempts: 60 });
  if (res.status !== "SUCCESS") throw new Error(`tx ${sent.hash} ${res.status}`);
  return res.returnValue;
}

const upload = async (kp, name) =>
  (await submitOp(kp, Operation.uploadContractWasm({ wasm: wasm(name) }))).bytes();

async function create(kp, wasmHash, ctorArgs) {
  const rv = await submitOp(
    kp,
    Operation.createCustomContract({
      address: new Address(kp.publicKey()),
      wasmHash,
      constructorArgs: ctorArgs,
      salt: Buffer.from(Keypair.random().rawPublicKey()),
    }),
  );
  return Address.fromScVal(rv).toString();
}

/** Run `fn`, expecting the contract to reject it with error `code`. */
async function expectContractError(name, code, fn) {
  try {
    await fn();
    check(name, false, "expected a rejection, but it succeeded");
  } catch (e) {
    const raw = String(e?.message ?? e);
    check(name, parseContractErrorCode(raw) === code, `got: ${humanizeContractError(raw) ?? raw.slice(0, 200)}`);
  }
}

// ---------------------------------------------------------------------------
// Deployment
// ---------------------------------------------------------------------------

const admin = Keypair.random();
const alice = Keypair.random();
const bob = Keypair.random();
await Promise.all([fund(admin), fund(alice), fund(bob)]);
const ADMIN = admin.publicKey();
const A = alice.publicKey();
const B = bob.publicKey();

const native = Asset.native().contractId(PASSPHRASE);
try {
  await submitOp(admin, Operation.createStellarAssetContract({ asset: Asset.native() }));
} catch {
  // Already deployed on this network — fine.
}

const verifier = await create(admin, await upload(admin, "verifier"), [addr(ADMIN), addr(ADMIN)]);
const auditorReg = await create(admin, await upload(admin, "auditor"), [addr(ADMIN), addr(ADMIN)]);
const factory = await create(admin, await upload(admin, "factory"), [
  xdr.ScVal.scvBytes(await upload(admin, "compliant_token")),
  xdr.ScVal.scvBytes(await upload(admin, "allowlist_policy")),
]);

const client = new ChainClient({
  rpcUrl: RPC_URL,
  networkPassphrase: PASSPHRASE,
  contracts: { token: "", verifier, auditor: auditorReg },
});
const adminSigner = keypairSigner(admin.secret(), PASSPHRASE);
const aSigner = keypairSigner(alice.secret(), PASSPHRASE);
const bSigner = keypairSigner(bob.secret(), PASSPHRASE);
const fromLedger = await client.latestLedger();

console.log("factory:");
const wiring = { factory, underlying: native, verifier, auditor: auditorReg };
const SALT = 7;
const { policy, token } = await deployAllowlistAndToken(
  client,
  adminSigner,
  wiring,
  { policyAdmin: ADMIN, policyManager: ADMIN, tokenAdmin: ADMIN, sacPassthrough: false },
  SALT,
);
client.cfg.contracts.token = token;
check(
  "predict_token_address matches the deployed token",
  (await predictTokenAddress(client, wiring, ADMIN, { policy, sacPassthrough: false }, SALT)) === token,
);
check("token compliance config points at the allowlist", (await readComplianceConfig(client, token))?.policy === policy);
check("token admin is the deployer", (await readAdmin(client, token)) === ADMIN);
check("allowlist manager role granted by its constructor", await hasRole(client, policy, ADMIN, MANAGER_ROLE));
check("token grants no role at construction", !(await hasRole(client, token, ADMIN, TOKEN_ROLES.freezer)));
console.log(`  token ${token}\n  policy ${policy}`);

for (const [name, circuitType] of [
  ["register", CIRCUIT_TYPE.Register],
  ["withdraw", CIRCUIT_TYPE.Withdraw],
  ["transfer", CIRCUIT_TYPE.Transfer],
  ["spender_transfer", CIRCUIT_TYPE.SpenderTransfer],
  ["set_spender", CIRCUIT_TYPE.SetSpender],
  ["clawback", CIRCUIT_TYPE.Clawback],
]) {
  const vk = readFileSync(new URL(`../circuits/vks/${name}.vk.bin`, import.meta.url));
  await client.invoke(
    verifier,
    "register_verification_key",
    [xdr.ScVal.scvU32(circuitType), xdr.ScVal.scvBytes(vk), addr(ADMIN)],
    adminSigner,
  );
}

const kSecret = randomScalar();
const kAud = scalarMul(kSecret, H);
await client.invoke(
  auditorReg,
  "register_key",
  [xdr.ScVal.scvU32(0), xdr.ScVal.scvBytes(Buffer.from(pointToBytes(kAud))), addr(ADMIN)],
  adminSigner,
);
check("registered six VKs + auditor key 0", (await client.auditorKey(0)).equals(kAud));

for (const who of [A, B]) await allowUser(client, adminSigner, policy, who, ADMIN);
check("alice and bob allowlisted", (await isAllowed(client, policy, A)) && (await isAllowed(client, policy, B)));

// ---------------------------------------------------------------------------
// Holder flow
// ---------------------------------------------------------------------------

const addrF = addressToField(token);
const aKeys = deriveKeys(randomScalar(), addrF);
const bKeys = deriveKeys(randomScalar(), addrF);
const engineFor = (keys, address) =>
  new StateEngine({ client, store: new MemoryStore(), keys, address, fromLedger });
const aEngine = engineFor(aKeys, A);
const bEngine = engineFor(bKeys, B);

const provers = {
  register: new CircuitProver(loadCircuit("register")),
  withdraw: new CircuitProver(loadCircuit("withdraw")),
  transfer: new CircuitProver(loadCircuit("transfer")),
  clawback: new CircuitProver(loadCircuit("clawback")),
};

/** Local openings must re-commit to the on-chain points. */
async function expectOpenings(who, spend, receive) {
  const acct = await client.confidentialBalance(who === "alice" ? A : B);
  check(
    `${who}: spendable opening matches on-chain C_spend`,
    acct && acct.spendableBalance.equals(commit(spend.v, spend.r)),
  );
  check(
    `${who}: receiving opening matches on-chain C_receive`,
    acct && acct.receivingBalance.equals(commit(receive.v, receive.r)),
  );
}

/** StateEngine.sync from real events, which ends in the consistency check. */
async function expectSync(who, engine) {
  const s = await engine.sync().catch((e) => e);
  check(`${who}: StateEngine.sync verifies against chain`, !(s instanceof Error), s?.message);
  return s instanceof Error ? null : s;
}

/** Thrown by step() after it has recorded the failure, so the outer catch doesn't count it twice. */
class StepFailed extends Error {}

async function step(name, fn) {
  try {
    await fn();
    check(`${name} accepted on-chain`, true);
  } catch (e) {
    check(`${name} accepted on-chain`, false, String(e?.message ?? e).split("\n")[0]);
    throw new StepFailed(name, { cause: e });
  }
}

/** Clawback witness, built inline: the SDK has no clawback builder yet. */
async function clawbackInputs(account, state, amount, destination) {
  const acct = await client.confidentialBalance(account);
  return {
    k_aud: fieldIn(kSecret),
    v_s: fieldIn(state.spendable.v),
    r_s: fieldIn(state.spendable.r),
    v_r: fieldIn(state.receiving.v),
    r_r: fieldIn(state.receiving.r),
    ...pointIn("c_spend", acct.spendableBalance),
    ...pointIn("c_receive", acct.receivingBalance),
    ...pointIn("k_aud", kAud),
    alpha: fieldIn(amount),
    addr_f: fieldIn(addrF),
    _acct_f: fieldIn(addressToField(account)),
    _dest_f: fieldIn(destination ? addressToField(destination) : 0n),
    _nonce: fieldIn(BigInt(await clawbackNonce(client, token, account))),
  };
}

try {
  console.log("\nregister:");
  for (const [who, keys, signer, account] of [
    ["alice", aKeys, aSigner, A],
    ["bob", bKeys, bSigner, B],
  ]) {
    const w = buildRegisterWitness(keys, account);
    const { proof } = await provers.register.prove(w.inputs);
    await step(`register ${who}`, () => submitRegister(client, signer, account, 0, w, proof));
  }
  await expectOpenings("alice", { v: 0n, r: 0n }, { v: 0n, r: 0n });

  console.log("\ndeposit + merge:");
  const DEPOSIT = 5_000_000n;
  await step("deposit alice→alice", () => submitDeposit(client, aSigner, A, A, DEPOSIT));
  await expectOpenings("alice", { v: 0n, r: 0n }, { v: DEPOSIT, r: 0n });
  await step("merge alice", () => submitMerge(client, aSigner, A));
  await expectOpenings("alice", { v: DEPOSIT, r: 0n }, { v: 0n, r: 0n });

  console.log("\ntransfer alice→bob:");
  const SENT = 1_250_000n;
  const tw = buildTransferWitness({
    keys: aKeys,
    v: DEPOSIT,
    r: 0n,
    amount: SENT,
    pvkB: bKeys.PVK,
    kAudR: kAud,
    kAudS: kAud,
  });
  const tProof = await provers.transfer.prove(tw.inputs);
  await step("transfer (25 public inputs)", () => submitTransfer(client, aSigner, A, B, tw, tProof.proof));
  await expectOpenings("alice", tw.next, { v: 0n, r: 0n });
  await expectOpenings("bob", { v: 0n, r: 0n }, { v: SENT, r: tw.recipientView.rTransfer });

  console.log("\nwithdraw alice→alice:");
  const WITHDRAWN = 1_000_000n;
  const ww = buildWithdrawWitness({ keys: aKeys, v: tw.next.v, r: tw.next.r, amount: WITHDRAWN, kAudS: kAud });
  const wProof = await provers.withdraw.prove(ww.inputs);
  await step("withdraw (16 public inputs)", () =>
    submitWithdraw(client, aSigner, A, A, WITHDRAWN, ww, wProof.proof),
  );
  await expectOpenings("alice", ww.next, { v: 0n, r: 0n });

  console.log("\nstate engine (real events → replay → consistency check):");
  const aState = await expectSync("alice", aEngine);
  check(
    "alice: replayed spendable == post-withdraw opening",
    aState?.spendable.v === ww.next.v && aState?.spendable.r === ww.next.r,
  );
  const bState = await expectSync("bob", bEngine);
  check("bob: replayed receiving == the transfer credit", bState?.receiving.v === SENT);
  await step("merge bob", () => submitMerge(client, bSigner, B));
  const bMerged = await expectSync("bob", bEngine);
  check("bob: merge folded receiving into spendable", bMerged?.spendable.v === SENT && bMerged?.receiving.v === 0n);

  console.log("\nevents:");
  const { events } = await fetchEvents(client, { startLedger: fromLedger });
  const evT = events.find((e) => e.type === "transfer");
  const evW = events.find((e) => e.type === "withdraw");
  check(
    "transfer event carries the submitted r_tilde_aud_s",
    evT?.rAudS === tw.payload.rAudS && evT?.bAudS === tw.payload.bAudS,
  );
  check("withdraw event carries the submitted r_tilde_aud_s", evW?.rAudS === ww.payload.rAudS);

  console.log("\nauditor:");
  const at = auditTransfer(kSecret, evT);
  check("auditor: transfer amount + channel agreement", at.amount === SENT && at.channelsAgree);
  check(
    "auditor: sender channel opens alice's post-transfer C_spend",
    commit(at.senderBalance, at.senderBlinding).equals(tw.next.cSpend),
  );
  const aw = auditWithdraw(kSecret, evW);
  check(
    "auditor: withdraw checkpoint opens alice's post-withdraw C_spend",
    commit(aw.senderBalance, aw.senderBlinding).equals(ww.next.cSpend),
  );

  console.log("\ntransfer bob→alice (from bob's verified post-merge opening):");
  const BACK = 100_000n;
  const bOpening = await bEngine.spendableForProof();
  const tw2 = buildTransferWitness({
    keys: bKeys,
    v: bOpening.v,
    r: bOpening.r,
    amount: BACK,
    pvkB: aKeys.PVK,
    kAudR: kAud,
    kAudS: kAud,
  });
  const t2Proof = await provers.transfer.prove(tw2.inputs);
  await step("transfer bob→alice", () => submitTransfer(client, bSigner, B, A, tw2, t2Proof.proof));
  await expectSync("bob", bEngine);
  const aBeforeClaw = await expectSync("alice", aEngine);
  check("alice: receiving holds bob's credit", aBeforeClaw?.receiving.v === BACK);

  console.log("\nallowlist:");
  await disallowUser(client, adminSigner, policy, B, ADMIN);
  await expectContractError("disallowed bob cannot merge (3602)", 3602, () => submitMerge(client, bSigner, B));
  await allowUser(client, adminSigner, policy, B, ADMIN);
  check("bob re-allowed", await isAllowed(client, policy, B));

  console.log("\nroles + freeze:");
  for (const role of Object.values(TOKEN_ROLES)) {
    await grantRole(client, adminSigner, token, ADMIN, role, ADMIN);
  }
  check("admin holds freezer/config_manager/clawback", (
    await Promise.all(Object.values(TOKEN_ROLES).map((r) => hasRole(client, token, ADMIN, r)))
  ).every(Boolean));
  await expectContractError("clawback of an unfrozen account rejected (3604)", 3604, async () =>
    clawback(client, adminSigner, token, A, 1n, undefined, new Uint8Array(14592), ADMIN),
  );
  await step("freeze alice", () => freezeAccount(client, adminSigner, token, A, ADMIN));
  check("is_frozen(alice)", await isFrozen(client, token, A));
  await expectContractError("frozen alice cannot deposit (3601)", 3601, () => submitDeposit(client, aSigner, A, A, 1n));

  console.log("\nclawback (auditor proof, admin submits):");
  const CLAW1 = 300_000n;
  const c1 = await provers.clawback.prove(await clawbackInputs(A, aBeforeClaw, CLAW1, undefined));
  await step("clawback alice, destination None", () =>
    clawback(client, adminSigner, token, A, CLAW1, undefined, c1.proof, ADMIN),
  );
  const aAfter1 = await expectSync("alice", aEngine);
  check(
    "alice: clawback folded receiving and subtracted the amount",
    aAfter1?.spendable.v === aBeforeClaw.spendable.v + BACK - CLAW1 && aAfter1?.receiving.v === 0n,
  );
  check("clawback nonce advanced to 1", (await clawbackNonce(client, token, A)) === 1);

  const CLAW2 = 1n;
  const c2 = await provers.clawback.prove(await clawbackInputs(A, aAfter1, CLAW2, ADMIN));
  await step("clawback alice, destination Some(admin)", () =>
    clawback(client, adminSigner, token, A, CLAW2, ADMIN, c2.proof, ADMIN),
  );
  const aAfter2 = await expectSync("alice", aEngine);
  check("alice: second clawback replayed", aAfter2?.spendable.v === aAfter1.spendable.v - CLAW2);

  const claws = (await fetchEvents(client, { startLedger: fromLedger })).events.filter((e) => e.type === "clawback");
  check("clawback event with None destination decodes to null", claws[0]?.destination === null && claws[0]?.amount === CLAW1);
  check("clawback event with Some destination decodes to the address", claws[1]?.destination === ADMIN);

  console.log("\ncompliance config + unfreeze:");
  await step("set_compliance_config (policy None)", () =>
    setComplianceConfig(client, adminSigner, token, { policy: null, sacPassthrough: false }, ADMIN),
  );
  const cfg = await readComplianceConfig(client, token);
  check("compliance config read back without a policy", cfg && cfg.policy === null && cfg.sacPassthrough === false);
  // The constructor emits the first one (policy = the allowlist); the
  // rotation above emits the second, with policy None left out of the map.
  const cfgEvs = (await fetchEvents(client, { startLedger: fromLedger })).events.filter(
    (e) => e.type === "compliance_config_changed",
  );
  check("constructor's compliance_config_changed decodes Some(policy)", cfgEvs[0]?.policy === policy);
  check(
    "rotated compliance_config_changed with omitted policy decodes to null",
    cfgEvs.length === 2 && cfgEvs[1]?.policy === null && cfgEvs[1]?.sacPassthrough === false,
    JSON.stringify(cfgEvs.map((e) => ({ policy: e.policy, sac: e.sacPassthrough }))),
  );
  await step("unfreeze alice", () => unfreezeAccount(client, adminSigner, token, A, ADMIN));
  check("alice no longer frozen", !(await isFrozen(client, token, A)));
} catch (e) {
  // A failed step already recorded its failure; the rest depends on it.
  // Anything else (witness build, prove, a sync or event read outside a step)
  // is a failure no check() has seen yet.
  if (!(e instanceof StepFailed)) {
    check("scenario ran to completion", false, e?.stack ?? String(e));
  }
} finally {
  for (const p of Object.values(provers)) await p.destroy();
}

console.log(`\nonchain-e2e: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
