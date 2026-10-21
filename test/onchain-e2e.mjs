// On-chain end-to-end test against the upstream `examples/confidential`
// contracts — the only test where the Rust UltraHonk verifier, not bb.js,
// judges the SDK's proofs. It deploys a fresh verifier + auditor registry +
// compliant token, registers the committed VKs, and runs
// register → deposit → merge → transfer → withdraw with real proofs, checking
// after every step that the SDK's openings re-commit to the on-chain points and
// that the emitted events decode to exactly what was submitted.
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
  addressToField,
  auditTransfer,
  auditWithdraw,
  buildRegisterWitness,
  buildTransferWitness,
  buildWithdrawWitness,
  commit,
  deriveKeys,
  fetchEvents,
  keypairSigner,
  pointToBytes,
  randomScalar,
  scalarMul,
  scvStruct,
  submitDeposit,
  submitMerge,
  submitRegister,
  submitTransfer,
  submitWithdraw,
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

async function deployWasm(kp, name, ctorArgs) {
  const hash = await submitOp(kp, Operation.uploadContractWasm({ wasm: wasm(name) }));
  const salt = Buffer.from(Keypair.random().rawPublicKey());
  const rv = await submitOp(
    kp,
    Operation.createCustomContract({
      address: new Address(kp.publicKey()),
      wasmHash: hash.bytes(),
      constructorArgs: ctorArgs,
      salt,
    }),
  );
  return { id: Address.fromScVal(rv).toString(), wasmHash: hash.bytes() };
}

/** `ComplianceConfig { policy: Option<Address>, sac_passthrough: bool }`. */
const complianceConfig = (policy, sacPassthrough) =>
  scvStruct({
    policy: policy ? addr(policy) : xdr.ScVal.scvVoid(),
    sac_passthrough: xdr.ScVal.scvBool(sacPassthrough),
  });

// ---------------------------------------------------------------------------
// Deployment
// ---------------------------------------------------------------------------

const admin = Keypair.random();
const alice = Keypair.random();
const bob = Keypair.random();
await Promise.all([fund(admin), fund(alice), fund(bob)]);

const native = Asset.native().contractId(PASSPHRASE);
try {
  await submitOp(admin, Operation.createStellarAssetContract({ asset: Asset.native() }));
} catch {
  // Already deployed on this network — fine.
}

const verifier = await deployWasm(admin, "verifier", [addr(admin.publicKey()), addr(admin.publicKey())]);
const auditorReg = await deployWasm(admin, "auditor", [addr(admin.publicKey()), addr(admin.publicKey())]);

const client = new ChainClient({
  rpcUrl: RPC_URL,
  networkPassphrase: PASSPHRASE,
  contracts: { token: "", verifier: verifier.id, auditor: auditorReg.id },
});
const adminSigner = keypairSigner(admin.secret(), PASSPHRASE);
const fromLedger = await client.latestLedger();

const token = await deployWasm(admin, "compliant_token", [
  addr(admin.publicKey()),
  addr(native),
  addr(verifier.id),
  addr(auditorReg.id),
  complianceConfig(undefined, false),
]);
client.cfg.contracts.token = token.id;
console.log(`deployed: verifier ${verifier.id}\n          auditor  ${auditorReg.id}\n          token    ${token.id}\n`);

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
    verifier.id,
    "register_verification_key",
    [xdr.ScVal.scvU32(circuitType), xdr.ScVal.scvBytes(vk), addr(admin.publicKey())],
    adminSigner,
  );
}
console.log("registered all six VKs");

const kSecret = randomScalar();
const kAud = scalarMul(kSecret, H);
await client.invoke(
  auditorReg.id,
  "register_key",
  [xdr.ScVal.scvU32(0), xdr.ScVal.scvBytes(Buffer.from(pointToBytes(kAud))), addr(admin.publicKey())],
  adminSigner,
);
check("auditor key 0 reads back", (await client.auditorKey(0)).equals(kAud));

// ---------------------------------------------------------------------------
// Holder flow
// ---------------------------------------------------------------------------

const addrF = addressToField(token.id);
const aKeys = deriveKeys(randomScalar(), addrF);
const bKeys = deriveKeys(randomScalar(), addrF);
const aSigner = keypairSigner(alice.secret(), PASSPHRASE);
const bSigner = keypairSigner(bob.secret(), PASSPHRASE);
const A = alice.publicKey();
const B = bob.publicKey();

const provers = {
  register: new CircuitProver(loadCircuit("register")),
  withdraw: new CircuitProver(loadCircuit("withdraw")),
  transfer: new CircuitProver(loadCircuit("transfer")),
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

async function step(name, fn) {
  try {
    await fn();
    check(`${name} accepted on-chain`, true);
  } catch (e) {
    check(`${name} accepted on-chain`, false, String(e?.message ?? e).split("\n")[0]);
    throw e;
  }
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

  console.log("\nevents:");
  const { events } = await fetchEvents(client, { startLedger: fromLedger });
  const evT = events.find((e) => e.type === "transfer");
  const evW = events.find((e) => e.type === "withdraw");
  check("transfer event decoded", !!evT);
  check("withdraw event decoded", !!evW);
  check(
    "transfer event carries the submitted r_tilde_aud_s",
    evT?.rAudS === tw.payload.rAudS && evT?.bAudS === tw.payload.bAudS,
  );
  check("withdraw event carries the submitted r_tilde_aud_s", evW?.rAudS === ww.payload.rAudS);
  check(
    "event types seen: register×2, deposit, merge, transfer, withdraw",
    ["register", "register", "deposit", "merge", "transfer", "withdraw"].every(
      (t, i, all) => events.filter((e) => e.type === t).length === all.filter((x) => x === t).length,
    ),
    events.map((e) => e.type).join(","),
  );

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
} catch {
  // A failed step already recorded its failure; the rest depends on it.
} finally {
  for (const p of Object.values(provers)) await p.destroy();
}

console.log(`\nonchain-e2e: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
