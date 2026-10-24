// End-to-end proving test: generate a real UltraHonk proof (keccak transcript)
// for each circuit and locally verify it. Pins what the contract must receive
// (proof bytes = the verifier's PROOF_BYTES, public-input count) and that the
// VK bb.js derives from each circuit JSON is byte-identical to the committed
// circuits/vks/<name>.vk.bin — the key registered with the on-chain verifier.
//
// Requires the Barretenberg CRS. bb.js fetches it on first run (network) and
// caches under ~/.bb-crs; offline environments will fail here — that's a
// proving-environment limitation, not a correctness problem (witness
// correctness is already covered by parity.mjs).
import { deriveKeys } from "../src/crypto/keys.ts";
import { addressToField } from "../src/crypto/address.ts";
import { G, scalarMul } from "../src/crypto/grumpkin.ts";
import { randomScalar } from "../src/crypto/field.ts";
import { buildRegisterWitness } from "../src/witness/register.ts";
import { buildWithdrawWitness } from "../src/witness/withdraw.ts";
import { buildTransferWitness } from "../src/witness/transfer.ts";
import { buildSetSpenderWitness } from "../src/witness/set-spender.ts";
import { buildSpenderTransferWitness } from "../src/witness/spender-transfer.ts";
import { recoverEscrowedDvk } from "../src/crypto/delegation.ts";
import { CircuitProver } from "../src/proving/prover.ts";
import { loadCircuit } from "../src/proving/artifacts.ts";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const VKS = join(dirname(fileURLToPath(import.meta.url)), "..", "circuits", "vks");
const PROOF_BYTES = 14592;
const PUBLIC_INPUTS = { register: 6, withdraw: 16, transfer: 25, set_spender: 26, spender_transfer: 25 };

const TOKEN = "CCREDIB3DG3IBVUKBL7QMEK4MTPSTODR7MQ34QY4SQ5LZ5L4WFWNVNXG";
const addrF = addressToField(TOKEN);
// The registering account, bound into the register proof as `acct_f`.
const ACCOUNT = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
const auditorKey = () => scalarMul(randomScalar(), G);

let pass = 0,
  fail = 0;

async function proveAndVerify(name, buildInputs) {
  const prover = new CircuitProver(loadCircuit(name));
  try {
    const t0 = performance.now();
    const result = await prover.prove(buildInputs());
    const ms = Math.round(performance.now() - t0);
    const ok = await prover.verify(result);
    const vk = await prover.verificationKey();
    const committed = readFileSync(join(VKS, `${name}.vk.bin`));
    if (!Buffer.from(vk).equals(committed)) {
      fail++;
      console.error(`  ✗ ${name}: derived VK (${vk.length}B) != circuits/vks/${name}.vk.bin (${committed.length}B)`);
    } else if (result.proof.length !== PROOF_BYTES || result.publicInputs.length !== PUBLIC_INPUTS[name]) {
      fail++;
      console.error(
        `  ✗ ${name}: proof ${result.proof.length}B / ${result.publicInputs.length} PIs, ` +
          `expected ${PROOF_BYTES}B / ${PUBLIC_INPUTS[name]}`,
      );
    } else if (ok) {
      pass++;
      console.log(
        `  ✓ ${name}: proof ${result.proof.length}B, ${result.publicInputs.length} public inputs, VK == vks/${name}.vk.bin, verified (${ms}ms)`,
      );
    } else {
      fail++;
      console.error(`  ✗ ${name}: local verify returned false`);
    }
  } catch (e) {
    fail++;
    console.error(`  ✗ ${name}: ${String(e.message || e).split("\n")[0]}`);
  } finally {
    await prover.destroy();
  }
}

console.log("proving (UltraHonk + keccak):");

await proveAndVerify("register", () => {
  const keys = deriveKeys(randomScalar(), addrF);
  return buildRegisterWitness(keys, ACCOUNT).inputs;
});

await proveAndVerify("withdraw", () => {
  const keys = deriveKeys(randomScalar(), addrF);
  return buildWithdrawWitness({ keys, v: 1000n, r: 0n, amount: 400n, kAudS: auditorKey() }).inputs;
});

await proveAndVerify("transfer", () => {
  const sender = deriveKeys(randomScalar(), addrF);
  const recipient = deriveKeys(randomScalar(), addrF);
  return buildTransferWitness({
    keys: sender,
    v: 1000n,
    r: 0n,
    amount: 250n,
    pvkB: recipient.PVK,
    kAudR: auditorKey(),
    kAudS: auditorKey(),
  }).inputs;
});

// The spender_transfer witness is built from the set_spender one the way a
// spender would: dvk recovered from the escrow, never from the owner's vk.
const SPENDER = "GBPRIMWXMQQZGAP5YJLHTFSOLAOEYKUAJYH4A7ORYAAVIVBHTRWYZWFH";
const owner = deriveKeys(randomScalar(), addrF);
const spender = deriveKeys(randomScalar(), addrF);
const sw = buildSetSpenderWitness({
  keys: owner,
  v: 1000n,
  r: randomScalar(),
  amount: 300n,
  spender: SPENDER,
  yOp: spender.Y,
  kAudS: auditorKey(),
});

await proveAndVerify("set_spender", () => sw.inputs);

await proveAndVerify("spender_transfer", () => {
  const rec = recoverEscrowedDvk(spender.sk, addressToField(SPENDER), {
    escrowedDvk: sw.payload.escrowedDvk,
    aTilde: sw.payload.aTilde,
    allowanceSalt: sw.payload.sigmaA,
    allowanceCommitment: sw.payload.cA,
  });
  if (!rec) throw new Error("spender could not recover dvk");
  return buildSpenderTransferWitness({
    keys: spender,
    allowance: { dvk: rec.dvk, sigmaA: sw.payload.sigmaA, v: rec.opening.v },
    amount: 120n,
    pvkRecipient: deriveKeys(randomScalar(), addrF).PVK,
    kAudR: auditorKey(),
    kAudS: auditorKey(),
  }).inputs;
});

console.log(`\nprove: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
