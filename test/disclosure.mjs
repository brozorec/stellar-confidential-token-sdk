// Selective-disclosure (D-recipient) test, offline end-to-end:
//
//   1. Simulate the on-chain side: a real transfer witness produces the event
//      fields (R_e, sigma, v_tilde) exactly as the contract would emit them.
//   2. Holder side: build the disclosure witness, prove with the shared
//      committed disclosure artifact (UltraHonk, keccak transcript, ZK
//      flavour).
//   3. Receiver side: reconstruct the public-input vector the way
//      disclosure/verify.ts does (from "chain" values + own (P_R, ν), taking
//      only (R_disc, ṽ_disc) from the bundle), verify, decrypt, and check the
//      VK pin against circuits/disclosure/disclose_recipient.vk.json.
//   4. Tamper cases: wrong nonce, wrong recipient key, tampered ciphertext,
//      and a different event must all fail verification.
//
// The on-chain resolution half of the verifier (resolveEventRef +
// confidential_balance reads) needs a live network; this test pins
// everything that doesn't.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { xdr, Address, Keypair } from "@stellar/stellar-sdk";

import { deriveKeys } from "../src/crypto/keys.ts";
import { addressToField } from "../src/crypto/address.ts";
import { randomScalar, toHex32, fromHex, toBytes32BE } from "../src/crypto/field.ts";
import { pointCoords, pointToBytes } from "../src/crypto/grumpkin.ts";
import { G, scalarMul } from "../src/crypto/grumpkin.ts";
import { recoverEscrowedDvk } from "../src/crypto/delegation.ts";
import { buildTransferWitness } from "../src/witness/transfer.ts";
import { buildSetSpenderWitness } from "../src/witness/set-spender.ts";
import { buildSpenderTransferWitness } from "../src/witness/spender-transfer.ts";
import { naturalEventId, resolveEventRef } from "../src/chain/events.ts";
import { scvStruct } from "../src/chain/payload.ts";
import { proveRecipientDisclosure, proveSenderDisclosure } from "../src/disclosure/prove.ts";
import { CircuitProver } from "../src/proving/prover.ts";
import {
  generateRecipientKeys,
  newDisclosureRequest,
  decryptDisclosure,
  pointFromJson,
} from "../src/disclosure/recipient.ts";
import { buildDiscloseRecipientWitness } from "../src/witness/disclose-recipient.ts";
import { buildDiscloseSenderWitness, NotDisclosableError } from "../src/witness/disclose-sender.ts";
import { verifyDisclosure, DisclosureVerifyError } from "../src/disclosure/verify.ts";

const here = dirname(fileURLToPath(import.meta.url));
const artifactsDir = join(here, "..", "circuits", "disclosure");
const loadArtifact = (n) => JSON.parse(readFileSync(join(artifactsDir, n), "utf8"));
const circuit = loadArtifact("disclose_recipient.json");
const vkJson = loadArtifact("disclose_recipient.vk.json");
const senderCircuit = loadArtifact("disclose_sender.json");
const senderVkJson = loadArtifact("disclose_sender.vk.json");

const TOKEN = "CBF64DEOVQAXJFBSNGFEUT2AH4H7K5JBY3ZYJ5GVEINMNSDISWRG5N3F";
const addrF = addressToField(TOKEN);

let pass = 0,
  fail = 0;
const check = (ok, label) => {
  if (ok) {
    pass++;
    console.log(`  ✓ ${label}`);
  } else {
    fail++;
    console.error(`  ✗ ${label}`);
  }
};

// --- 1. the "on-chain" event -------------------------------------------------
const sender = deriveKeys(randomScalar(), addrF);
const holder = deriveKeys(randomScalar(), addrF); // the event's `to` account
const AMOUNT = 250n;
const tw = buildTransferWitness({
  keys: sender,
  v: 1000n,
  r: 0n,
  amount: AMOUNT,
  pvkB: holder.PVK,
  kAudR: scalarMul(randomScalar(), G),
  kAudS: scalarMul(randomScalar(), G),
});
const event = { rE: tw.payload.rE, sigma: tw.payload.sigma, vTilde: tw.payload.vTilde };

// --- 2. holder proves --------------------------------------------------------
const receiver = generateRecipientKeys();
const request = newDisclosureRequest(receiver);

const w = buildDiscloseRecipientWitness({
  keys: holder,
  event,
  pR: pointFromJson(request.pR),
  nu: fromHex(request.nu),
});
check(w.vTx === AMOUNT, `witness decrypts the event amount in-circuit-shape (${w.vTx})`);

const prover = new CircuitProver(circuit, { zk: true });
const t0 = performance.now();
const { proof, publicInputs } = await prover.prove(w.inputs);
console.log(
  `  · proof ${proof.length}B, ${publicInputs.length} public inputs (${Math.round(performance.now() - t0)}ms)`,
);

// --- 3. receiver verifies ----------------------------------------------------
// VK pin: bytecode-derived VK must equal the committed artifact.
const vk = await prover.verificationKey();
check(
  Buffer.from(vk).toString("base64") === vkJson.vkBase64,
  "VK derived from circuit bytecode matches the pinned circuits/disclosure/disclose_recipient.vk.json",
);
check(vkJson.zk === true && senderVkJson.zk === true, "VK pins record the ZK flavour");

// Public inputs rebuilt the receiver-protocol way (chain values + own (P_R, ν) + the
// bundle's R_disc / ṽ_disc) — byte-equal to what bb.js extracted.
const rDiscCoords = pointCoords(w.rDisc);
const rebuilt = [
  addrF,
  pointCoords(holder.PVK).x,
  pointCoords(holder.PVK).y,
  pointCoords(event.rE).x,
  pointCoords(event.rE).y,
  event.sigma,
  event.vTilde,
  fromHex(request.pR.x),
  fromHex(request.pR.y),
  fromHex(request.nu),
  rDiscCoords.x,
  rDiscCoords.y,
  w.vTildeDisc,
].map(toHex32);
check(
  JSON.stringify(rebuilt) === JSON.stringify(publicInputs.map((h) => toHex32(fromHex(h)))),
  "verifier-rebuilt public-input vector equals the prover's",
);

check(await prover.verify({ proof, publicInputs: rebuilt }), "UltraHonk proof verifies");

const amount = decryptDisclosure(receiver.rR, w.rDisc, w.vTildeDisc, fromHex(request.nu));
check(amount === AMOUNT, `receiver decrypts the disclosed amount (${amount})`);

// --- 4. tamper cases ---------------------------------------------------------
const tamper = async (label, mutate) => {
  const pi = [...rebuilt];
  mutate(pi);
  check(!(await prover.verify({ proof, publicInputs: pi })), label);
};
await tamper("rejects a different request nonce (replay)", (pi) => (pi[9] = toHex32(fromHex(request.nu) + 1n)));
await tamper("rejects a different recipient key", (pi) => {
  const other = generateRecipientKeys();
  pi[7] = toHex32(fromHex(other.pR.x));
  pi[8] = toHex32(fromHex(other.pR.y));
});
await tamper("rejects a tampered disclosure ciphertext", (pi) => (pi[12] = toHex32(w.vTildeDisc + 1n)));
await tamper("rejects binding to a different event (R_e swap)", (pi) => {
  const otherRe = scalarMul(randomScalar(), G);
  pi[3] = toHex32(pointCoords(otherRe).x);
  pi[4] = toHex32(pointCoords(otherRe).y);
});

// A wrong recipient secret must not silently decrypt to a plausible value.
const wrong = decryptDisclosure(randomScalar(), w.rDisc, w.vTildeDisc, fromHex(request.nu));
check(wrong !== AMOUNT, "wrong recipient secret does not recover the amount");

// Flavour: the VK is identical across flavours, so only the verify itself can
// catch a non-ZK proof — it must fail closed.
const nonZk = new CircuitProver(circuit);
const nonZkProof = await nonZk.prove(w.inputs);
check(!(await prover.verify({ proof: nonZkProof.proof, publicInputs: rebuilt })), "a non-ZK proof does not verify as a disclosure proof");
check(
  Buffer.from(await nonZk.verificationKey()).toString("base64") === vkJson.vkBase64,
  "(VK bytes are flavour-independent — which is why the pin cannot enforce ZK)",
);

// verifyDisclosure's vk-pinning stage runs before any chain access.
const stageOf = async (overrides) => {
  try {
    await verifyDisclosure({
      client: {},
      bundle: { circuitId: "disclose_recipient", refE: { ledger: 1, id: "x" }, proof: "0x", rDisc: request.pR, vTildeDisc: "0x01" },
      request,
      keys: receiver,
      prover,
      pinnedVk: Buffer.from(vkJson.vkBase64, "base64"),
      ...overrides,
    });
  } catch (e) {
    return e instanceof DisclosureVerifyError ? e.stage : `untyped: ${e.message}`;
  }
  return "accepted";
};
check((await stageOf({ prover: nonZk })) === "vk-pinning", "verifyDisclosure rejects a non-ZK prover at vk-pinning");
check(
  (await stageOf({ pinnedVk: Buffer.from(senderVkJson.vkBase64, "base64") })) === "vk-pinning",
  "verifyDisclosure rejects a mismatched pinned VK at vk-pinning",
);

await nonZk.destroy();
await prover.destroy();

// --- 5. D-sender: the originator proves the same event from their side ------
console.log("\nD-sender:");
const senderReceiver = generateRecipientKeys();
const senderRequest = newDisclosureRequest(senderReceiver);

// Only the originator re-derives the event's r_e; anyone else gets the typed
// not-disclosable outcome before proving.
let notDisclosable = false;
try {
  buildDiscloseSenderWitness({
    keys: holder,
    event,
    pvkB: holder.PVK,
    pR: pointFromJson(senderRequest.pR),
    nu: fromHex(senderRequest.nu),
  });
} catch (e) {
  notDisclosable = e instanceof NotDisclosableError;
}
check(notDisclosable, "non-originator keys: NotDisclosableError, not a proving error");

const sw = buildDiscloseSenderWitness({
  keys: sender,
  event,
  pvkB: holder.PVK,
  pR: pointFromJson(senderRequest.pR),
  nu: fromHex(senderRequest.nu),
});
check(sw.vTx === AMOUNT, `sender witness reconstructs the event amount (${sw.vTx})`);

const senderProver = new CircuitProver(senderCircuit, { zk: true });
const t1 = performance.now();
const sp = await senderProver.prove(sw.inputs);
console.log(
  `  · proof ${sp.proof.length}B, ${sp.publicInputs.length} public inputs (${Math.round(performance.now() - t1)}ms)`,
);

const senderVk = await senderProver.verificationKey();
check(
  Buffer.from(senderVk).toString("base64") === senderVkJson.vkBase64,
  "VK derived from circuit bytecode matches the pinned circuits/disclosure/disclose_sender.vk.json",
);

// Receiver-protocol rebuild: PVK_A from the ORIGINATOR's account, PVK_B from the
// transfer recipient's, the rest from the event + the verifier's own request.
const sRDisc = pointCoords(sw.rDisc);
const senderRebuilt = [
  addrF,
  pointCoords(sender.PVK).x,
  pointCoords(sender.PVK).y,
  pointCoords(event.rE).x,
  pointCoords(event.rE).y,
  event.sigma,
  event.vTilde,
  pointCoords(holder.PVK).x,
  pointCoords(holder.PVK).y,
  fromHex(senderRequest.pR.x),
  fromHex(senderRequest.pR.y),
  fromHex(senderRequest.nu),
  sRDisc.x,
  sRDisc.y,
  sw.vTildeDisc,
].map(toHex32);
check(
  JSON.stringify(senderRebuilt) === JSON.stringify(sp.publicInputs.map((h) => toHex32(fromHex(h)))),
  "verifier-rebuilt sender public-input vector equals the prover's",
);
check(
  await senderProver.verify({ proof: sp.proof, publicInputs: senderRebuilt }),
  "UltraHonk sender proof verifies",
);

const senderAmount = decryptDisclosure(
  senderReceiver.rR, sw.rDisc, sw.vTildeDisc, fromHex(senderRequest.nu),
);
check(senderAmount === AMOUNT, `receiver decrypts the sender-disclosed amount (${senderAmount})`);

const senderTamper = async (label, mutate) => {
  const pi = [...senderRebuilt];
  mutate(pi);
  check(!(await senderProver.verify({ proof: sp.proof, publicInputs: pi })), label);
};
await senderTamper("rejects impersonation (PVK_A swapped to the recipient's account)", (pi) => {
  pi[1] = toHex32(pointCoords(holder.PVK).x);
  pi[2] = toHex32(pointCoords(holder.PVK).y);
});
await senderTamper("rejects a substituted transfer recipient (PVK_B swap)", (pi) => {
  const other = deriveKeys(randomScalar(), addrF);
  pi[7] = toHex32(pointCoords(other.PVK).x);
  pi[8] = toHex32(pointCoords(other.PVK).y);
});
await senderTamper("rejects a different request nonce (replay)", (pi) => {
  pi[11] = toHex32(fromHex(senderRequest.nu) + 1n);
});

await senderProver.destroy();

// --- 6. SpenderTransfer: the same circuits, σ_E = σ_a', originator = spender.
// Runs the full receiver protocol (verifyDisclosure) over a stub chain that
// serves a real spender_transfer event through the RPC decoder.
console.log("\nSpenderTransfer (verifyDisclosure end to end, stub chain):");
const OWNER = Keypair.random().publicKey();
const SPENDER = Keypair.random().publicKey();
const HOLDER = Keypair.random().publicKey();
const ownerKeys = deriveKeys(randomScalar(), addrF);
const spenderKeys = deriveKeys(randomScalar(), addrF);
const audKey = scalarMul(randomScalar(), G);
const ssw = buildSetSpenderWitness({
  keys: ownerKeys, v: 1000n, r: 0n, amount: 400n, spender: SPENDER, yOp: spenderKeys.Y, kAudS: audKey,
});
const rec = recoverEscrowedDvk(spenderKeys.sk, addressToField(SPENDER), {
  escrowedDvk: ssw.payload.escrowedDvk, aTilde: ssw.payload.aTilde,
  allowanceSalt: ssw.payload.sigmaA, allowanceCommitment: ssw.payload.cA,
});
const SPENT = 175n;
const stw = buildSpenderTransferWitness({
  keys: spenderKeys, allowance: { dvk: rec.dvk, sigmaA: ssw.payload.sigmaA, v: rec.opening.v },
  amount: SPENT, pvkRecipient: holder.PVK, kAudR: audKey, kAudS: audKey,
});
const LEDGER = 4242, TX = "ab".repeat(32);
const fb = (v) => xdr.ScVal.scvBytes(Buffer.from(toBytes32BE(v)));
const q = stw.payload;
const rpcEvent = {
  id: `${(BigInt(LEDGER) << 32n).toString()}-0`, ledger: LEDGER, txHash: TX,
  topic: [xdr.ScVal.scvSymbol("spender_transfer"), ...[SPENDER, OWNER, HOLDER].map((a) => new Address(a).toScVal())],
  value: scvStruct({
    r_e_point: xdr.ScVal.scvBytes(Buffer.from(pointToBytes(q.rE))), v_tilde: fb(q.vTilde),
    sigma_a_new: fb(q.sigmaANew), v_tilde_aud_r: fb(q.vAudR), r_tilde_aud_r: fb(q.rAudR),
    v_tilde_aud_s: fb(q.vAudS), a_tilde_aud_s: fb(q.aAudS), r_tilde_aud_s: fb(q.rAudS),
  }),
};
const accountOf = (k) => ({ spendingKey: k.Y, viewingPublicKey: k.PVK, spendableBalance: k.Y, receivingBalance: k.Y, auditorId: 0 });
let accounts = { [OWNER]: accountOf(ownerKeys), [SPENDER]: accountOf(spenderKeys), [HOLDER]: accountOf(holder) };
const stubChain = {
  cfg: { contracts: { token: TOKEN } },
  server: { getEvents: async () => ({ events: [rpcEvent], latestLedger: LEDGER }) },
  confidentialBalance: async (a) => accounts[a] ?? null,
};
const ref = { ledger: LEDGER, id: naturalEventId({ ledger: LEDGER, txHash: TX, opIndex: 0, eventIndex: 0 }), txHash: TX };
const stEvent = await resolveEventRef(stubChain, ref);
check(stEvent?.type === "spender_transfer" && stEvent.spender === SPENDER, "ref_E resolves to the spender_transfer event");

// An untyped caller can hand the provers any decoded event. Anything but a
// Transfer / SpenderTransfer is refused before witness building, not as a
// TypeError from inside it.
const noProver = { zk: true, prove: async () => { throw new Error("reached the prover"); } };
const refusal = (p) => p.then(() => "accepted", (e) => (e instanceof TypeError ? `TypeError: ${e.message}` : e.message));
const strayBase = { ledger: LEDGER, id: ref.id, txHash: TX, rE: ssw.payload.rE, sigma: ssw.payload.sigma };
const setSpenderEv = { ...strayBase, type: "set_spender", account: OWNER, spender: SPENDER };
const withdrawEv = { ...strayBase, type: "withdraw", from: HOLDER, to: HOLDER, amount: 1n };
const rStray = await refusal(proveRecipientDisclosure({ keys: holder, event: setSpenderEv, request: newDisclosureRequest(receiver), prover: noProver }));
check(/not "set_spender"/.test(rStray), `D-recipient refuses a set_spender event up front → ${rStray}`);
const sStray = await refusal(proveSenderDisclosure({ keys: holder, event: withdrawEv, pvkB: holder.PVK, request: newDisclosureRequest(receiver), prover: noProver }));
check(/not "withdraw"/.test(sStray), `D-sender refuses a withdraw event up front → ${sStray}`);

const rProver = new CircuitProver(circuit, { zk: true });
const sProver = new CircuitProver(senderCircuit, { zk: true });
const verifyAs = (bundle, req, prover, vkPin) =>
  verifyDisclosure({ client: stubChain, bundle, request: req, keys: receiver, prover, pinnedVk: Buffer.from(vkPin.vkBase64, "base64") });

const req1 = newDisclosureRequest(receiver);
const rBundle = await proveRecipientDisclosure({ keys: holder, event: stEvent, request: req1, prover: rProver });
const rOut = await verifyAs(rBundle, req1, rProver, vkJson).catch((e) => e);
check(rOut?.amount === SPENT && rOut.role === "recipient" && rOut.disclosingAccount === HOLDER,
  `D-recipient on a SpenderTransfer verifies (σ_E = σ_a') → ${rOut?.amount ?? rOut?.message}`);

const req2 = newDisclosureRequest(receiver);
const sOut = await proveSenderDisclosure({ keys: spenderKeys, event: stEvent, pvkB: holder.PVK, request: req2, prover: sProver });
check(sOut.disclosable, "the spender can D-sender its spender transfer");
const sVer = await verifyAs(sOut.bundle, req2, sProver, senderVkJson).catch((e) => e);
check(sVer?.amount === SPENT && sVer.role === "sender" && sVer.disclosingAccount === SPENDER,
  `D-sender verifies with PVK_A read from E.spender → ${sVer?.amount ?? sVer?.message}`);

const ownerTry = await proveSenderDisclosure({ keys: ownerKeys, event: stEvent, pvkB: holder.PVK, request: req2, prover: sProver });
check(!ownerTry.disclosable, "the owner cannot D-sender it (coverage asymmetry): not disclosable, not an error");

// If the verifier read PVK_A from E.from (the owner) the statement would be
// about the wrong account: substitute the owner's key at the spender's address.
accounts = { ...accounts, [SPENDER]: accountOf(ownerKeys) };
const wrongA = await verifyAs(sOut.bundle, req2, sProver, senderVkJson).catch((e) => e);
check(wrongA instanceof DisclosureVerifyError && wrongA.stage === "verify-proof", "a different PVK at E.spender fails verify-proof");
accounts = { ...accounts, [SPENDER]: accountOf(spenderKeys) };
const replay = await verifyAs(rBundle, newDisclosureRequest(receiver), rProver, vkJson).catch((e) => e);
check(replay instanceof DisclosureVerifyError && replay.stage === "verify-proof", "a bundle replayed against a fresh request fails");

await rProver.destroy();
await sProver.destroy();
console.log(`\ndisclosure: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
