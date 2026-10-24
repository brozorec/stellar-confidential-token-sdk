// Circuit-parity test: the ultimate gate for the crypto + witness layers.
//
// For each circuit we build a witness entirely from SDK-side crypto (Grumpkin
// generators, Poseidon2 sponge, ECDH, the derivation formulas) and ask the
// REAL compiled circuit (via noir_js) to solve it. If execution succeeds, every
// in-circuit `assert(derived == public_input)` held — meaning the SDK computed
// Y, PVK, vk, C_spend', C_transfer, R_e, the encrypted scalars, and BOTH auditor
// channels exactly as the circuit does. Negative cases tamper one public input
// and require rejection, proving the test actually constrains.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Noir } from "@noir-lang/noir_js";

import { deriveKeys } from "../src/crypto/keys.ts";
import { addressToField } from "../src/crypto/address.ts";
import { G, commit, scalarMul } from "../src/crypto/grumpkin.ts";
import { randomScalar } from "../src/crypto/field.ts";
import { deriveAllowR } from "../src/crypto/poseidon2.ts";
import { fieldIn, pointIn } from "../src/witness/common.ts";
import { buildRegisterWitness } from "../src/witness/register.ts";
import { buildWithdrawWitness } from "../src/witness/withdraw.ts";
import { buildTransferWitness } from "../src/witness/transfer.ts";
import { buildSetSpenderWitness } from "../src/witness/set-spender.ts";
import { buildSpenderTransferWitness } from "../src/witness/spender-transfer.ts";
import { recoverEscrowedDvk } from "../src/crypto/delegation.ts";

const here = dirname(fileURLToPath(import.meta.url));
const circuit = (name) =>
  JSON.parse(readFileSync(join(here, "..", "circuits", `${name}.json`), "utf8"));

// Any valid 56-char strkey works as the bound token address.
const TOKEN = "CCREDIB3DG3IBVUKBL7QMEK4MTPSTODR7MQ34QY4SQ5LZ5L4WFWNVNXG";
const addrF = addressToField(TOKEN);
// The registering account, bound into the register proof as `acct_f` (L-06).
const ACCOUNT = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

// A mock auditor key: any on-curve, non-identity Grumpkin point.
const auditorKey = () => scalarMul(randomScalar(), G);

let pass = 0,
  fail = 0;
async function expectOk(name, fn) {
  try {
    await fn();
    pass++;
    console.log(`  ✓ ${name}`);
  } catch (e) {
    fail++;
    console.error(`  ✗ ${name}\n      ${String(e.message || e).split("\n")[0]}`);
  }
}
async function expectReject(name, fn) {
  try {
    await fn();
    fail++;
    console.error(`  ✗ ${name} (expected rejection, but it passed)`);
  } catch {
    pass++;
    console.log(`  ✓ ${name} (rejected as expected)`);
  }
}

const registerNoir = new Noir(circuit("register"));
const withdrawNoir = new Noir(circuit("withdraw"));
const transferNoir = new Noir(circuit("transfer"));
const setSpenderNoir = new Noir(circuit("set_spender"));
const spenderTransferNoir = new Noir(circuit("spender_transfer"));

console.log("register:");
await expectOk("SDK Y/PVK satisfy the circuit", async () => {
  const keys = deriveKeys(randomScalar(), addrF);
  const { inputs } = buildRegisterWitness(keys, ACCOUNT);
  await registerNoir.execute(inputs);
});
// No negative case for `acct_f`: it is referenced by no gate, so witness
// solving accepts any value. Its binding lives in the proof transcript and is
// only observable at verification (see witness/register.ts).
await expectReject("tampered PVK.x rejected", async () => {
  const keys = deriveKeys(randomScalar(), addrF);
  const { inputs } = buildRegisterWitness(keys, ACCOUNT);
  await registerNoir.execute({ ...inputs, pvk_x: "0x1" });
});

console.log("withdraw:");
await expectOk("deposit-funded partial withdraw (v=1000, a=400)", async () => {
  const keys = deriveKeys(randomScalar(), addrF);
  const { inputs } = buildWithdrawWitness({
    keys,
    v: 1000n,
    r: 0n,
    amount: 400n,
    kAudS: auditorKey(),
  });
  await withdrawNoir.execute(inputs);
});
await expectOk("full withdraw (v=1000, a=1000 → v_new=0)", async () => {
  const keys = deriveKeys(randomScalar(), addrF);
  const { inputs } = buildWithdrawWitness({ keys, v: 1000n, r: 0n, amount: 1000n, kAudS: auditorKey() });
  await withdrawNoir.execute(inputs);
});
await expectReject("tampered b_tilde_aud_s rejected", async () => {
  const keys = deriveKeys(randomScalar(), addrF);
  const { inputs } = buildWithdrawWitness({ keys, v: 1000n, r: 0n, amount: 400n, kAudS: auditorKey() });
  await withdrawNoir.execute({ ...inputs, b_tilde_aud_s: "0x123456" });
});
// W_a5: the escrowed blinding is the THIRD lane of the sender sponge over r'.
// A lane-1 pad (the old two-wide reading) or the raw r' must both fail.
await expectReject("tampered r_tilde_aud_s rejected", async () => {
  const keys = deriveKeys(randomScalar(), addrF);
  const { inputs } = buildWithdrawWitness({ keys, v: 1000n, r: 0n, amount: 400n, kAudS: auditorKey() });
  await withdrawNoir.execute({ ...inputs, r_tilde_aud_s: inputs.b_tilde_aud_s });
});

console.log("transfer:");
await expectOk("dual-auditor transfer (v=1000, v_tx=250)", async () => {
  const sender = deriveKeys(randomScalar(), addrF);
  const recipient = deriveKeys(randomScalar(), addrF);
  const { inputs } = buildTransferWitness({
    keys: sender,
    v: 1000n,
    r: 0n,
    amount: 250n,
    pvkB: recipient.PVK,
    kAudR: auditorKey(),
    kAudS: auditorKey(),
  });
  await transferNoir.execute(inputs);
});
await expectReject("tampered v_tilde_aud_r rejected", async () => {
  const sender = deriveKeys(randomScalar(), addrF);
  const recipient = deriveKeys(randomScalar(), addrF);
  const { inputs } = buildTransferWitness({
    keys: sender,
    v: 1000n,
    r: 0n,
    amount: 250n,
    pvkB: recipient.PVK,
    kAudR: auditorKey(),
    kAudS: auditorKey(),
  });
  await transferNoir.execute({ ...inputs, v_tilde_aud_r: "0xdead" });
});
await expectReject("tampered r_tilde_aud_s rejected", async () => {
  const sender = deriveKeys(randomScalar(), addrF);
  const recipient = deriveKeys(randomScalar(), addrF);
  const { inputs } = buildTransferWitness({
    keys: sender,
    v: 1000n,
    r: 0n,
    amount: 250n,
    pvkB: recipient.PVK,
    kAudR: auditorKey(),
    kAudS: auditorKey(),
  });
  await transferNoir.execute({ ...inputs, r_tilde_aud_s: "0xbeef" });
});

// A spender is a registered account on the same token; its address is op_i.
const SPENDER = "GBPRIMWXMQQZGAP5YJLHTFSOLAOEYKUAJYH4A7ORYAAVIVBHTRWYZWFH";
const setSpender = (overrides = {}) => {
  const owner = deriveKeys(randomScalar(), addrF);
  const spender = deriveKeys(randomScalar(), addrF);
  const w = buildSetSpenderWitness({
    keys: owner,
    v: 1000n,
    r: randomScalar(),
    amount: 300n,
    spender: SPENDER,
    yOp: spender.Y,
    kAudS: auditorKey(),
    ...overrides,
  });
  return { owner, spender, w };
};

console.log("set_spender:");
await expectOk("partial escrow (v=1000, v_a=300)", async () => {
  await setSpenderNoir.execute(setSpender().w.inputs);
});
await expectOk("full escrow (v_a = v → v_new = 0)", async () => {
  await setSpenderNoir.execute(setSpender({ amount: 1000n }).w.inputs);
});
await expectOk("zero allowance (v_a = 0)", async () => {
  await setSpenderNoir.execute(setSpender({ amount: 0n }).w.inputs);
});
// S12(a): the escrow's R_x IS R_e.x; a mask over -R_e would fail S12(c).
await expectReject("escrowed_dvk_r_x ≠ R_e.x rejected", async () => {
  const { inputs } = setSpender().w;
  await setSpenderNoir.execute({ ...inputs, escrowed_dvk_r_x: inputs.c_a_x });
});
await expectReject("tampered escrowed_dvk_cipher rejected", async () => {
  const { inputs } = setSpender().w;
  await setSpenderNoir.execute({ ...inputs, escrowed_dvk_cipher: inputs.a_tilde });
});
// op_i binds dvk (S5), the escrow mask (S12c) and the r_a escrow (S14).
await expectReject("op_i of another address rejected", async () => {
  const { inputs } = setSpender().w;
  await setSpenderNoir.execute({ ...inputs, op_i: "0x2a" });
});
// S14 is its own tag (17), not lane 2 of the sender sponge.
await expectReject("r_a_tilde_aud_s over the lane-2 pad rejected", async () => {
  const { inputs } = setSpender().w;
  await setSpenderNoir.execute({ ...inputs, r_a_tilde_aud_s: inputs.r_tilde_aud_s });
});
await expectReject("tampered v_tilde_aud_s rejected", async () => {
  const { inputs } = setSpender().w;
  await setSpenderNoir.execute({ ...inputs, v_tilde_aud_s: "0xdead" });
});

console.log("spender_transfer:");
// The spender's witness is built from what IT can recover: dvk from the
// on-chain escrow, the allowance from (a_tilde, σ_a) — never the owner's vk.
const delegate = (amount = 300n) => {
  const { spender, w } = setSpender({ amount });
  const entry = {
    escrowedDvk: w.payload.escrowedDvk,
    aTilde: w.payload.aTilde,
    allowanceSalt: w.payload.sigmaA,
    allowanceCommitment: w.payload.cA,
  };
  const rec = recoverEscrowedDvk(spender.sk, addressToField(SPENDER), entry);
  if (!rec) throw new Error("spender could not recover dvk from the escrow");
  return { spender, rec, allowance: { dvk: rec.dvk, sigmaA: entry.allowanceSalt, v: rec.opening.v } };
};
const spenderTransfer = (overrides = {}) => {
  const { spender, allowance } = delegate();
  return buildSpenderTransferWitness({
    keys: spender,
    allowance,
    amount: 120n,
    pvkRecipient: deriveKeys(randomScalar(), addrF).PVK,
    kAudR: auditorKey(),
    kAudS: auditorKey(),
    ...overrides,
  });
};
await expectOk("escrow recovered by the spender opens C_a and re-derives the owner's dvk", async () => {
  const { spender, w } = setSpender();
  const rec = recoverEscrowedDvk(spender.sk, addressToField(SPENDER), {
    escrowedDvk: w.payload.escrowedDvk,
    aTilde: w.payload.aTilde,
    allowanceSalt: w.payload.sigmaA,
    allowanceCommitment: w.payload.cA,
  });
  if (rec?.dvk !== w.allowance.dvk || rec.opening.v !== 300n || rec.opening.r !== w.allowance.r) {
    throw new Error("recovered allowance does not match the set_spender witness");
  }
});
await expectOk("escrow does not open for another spender key", async () => {
  const { w } = setSpender();
  const rec = recoverEscrowedDvk(randomScalar(), addressToField(SPENDER), {
    escrowedDvk: w.payload.escrowedDvk,
    aTilde: w.payload.aTilde,
    allowanceSalt: w.payload.sigmaA,
    allowanceCommitment: w.payload.cA,
  });
  if (rec !== null) throw new Error("a foreign key recovered a dvk");
});
await expectOk("set_spender → recovered dvk → spender_transfer (v_a=300, v_tx=120)", async () => {
  await spenderTransferNoir.execute(spenderTransfer().inputs);
});
await expectOk("spend the whole allowance (v_tx = v_a)", async () => {
  await spenderTransferNoir.execute(spenderTransfer({ amount: 300n }).inputs);
});
await expectOk("second spend from the post-transfer allowance", async () => {
  const { spender, allowance } = delegate();
  const first = buildSpenderTransferWitness({
    keys: spender, allowance, amount: 100n,
    pvkRecipient: deriveKeys(randomScalar(), addrF).PVK, kAudR: auditorKey(), kAudS: auditorKey(),
  });
  const second = buildSpenderTransferWitness({
    keys: spender,
    allowance: { dvk: allowance.dvk, sigmaA: first.next.sigmaA, v: first.next.v },
    amount: 50n,
    pvkRecipient: deriveKeys(randomScalar(), addrF).PVK, kAudR: auditorKey(), kAudS: auditorKey(),
  });
  await spenderTransferNoir.execute(second.inputs);
});
await expectReject("over-allowance amount rejected by the builder", async () => {
  spenderTransfer({ amount: 301n });
});
await expectReject("σ_a' = σ_a rejected by the builder (O14)", async () => {
  const { spender, allowance } = delegate();
  buildSpenderTransferWitness({
    keys: spender, allowance, amount: 1n, sigmaANew: allowance.sigmaA,
    pvkRecipient: deriveKeys(randomScalar(), addrF).PVK, kAudR: auditorKey(), kAudS: auditorKey(),
  });
});
// O14 in-circuit. Re-key the CURRENT allowance (σ_a, r_a, C_a — read by O2/O3
// only) to a chosen salt, consistently. Any salt but σ_a' is accepted (the
// control), so σ_a' itself can only be rejected by the nonce-rotation check.
const rekeyCurrent = (w, dvk, vA, salt) => ({
  ...w.inputs,
  sigma_a: fieldIn(salt),
  r_a: fieldIn(deriveAllowR(dvk, salt)),
  ...pointIn("c_a", commit(vA, deriveAllowR(dvk, salt))),
});
{
  const { spender, allowance } = delegate();
  const w = buildSpenderTransferWitness({
    keys: spender, allowance, amount: 1n,
    pvkRecipient: deriveKeys(randomScalar(), addrF).PVK, kAudR: auditorKey(), kAudS: auditorKey(),
  });
  await expectOk("control: current allowance re-keyed to an unrelated salt still solves", async () => {
    await spenderTransferNoir.execute(rekeyCurrent(w, allowance.dvk, allowance.v, randomScalar()));
  });
  await expectReject("σ_a' = σ_a rejected by the circuit (O14)", async () => {
    await spenderTransferNoir.execute(rekeyCurrent(w, allowance.dvk, allowance.v, w.payload.sigmaANew));
  });
}
await expectReject("dvk of another owner rejected (O3)", async () => {
  const { inputs } = spenderTransfer();
  await spenderTransferNoir.execute({ ...inputs, dvk_i: "0x1234" });
});
await expectReject("tampered a_tilde_aud_s rejected", async () => {
  const { inputs } = spenderTransfer();
  await spenderTransferNoir.execute({ ...inputs, a_tilde_aud_s: "0xbeef" });
});
await expectReject("tampered r_tilde_aud_r rejected", async () => {
  const { inputs } = spenderTransfer();
  await spenderTransferNoir.execute({ ...inputs, r_tilde_aud_r: inputs.r_tilde_aud_s });
});

console.log(`\nparity: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
