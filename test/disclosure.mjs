// Selective-disclosure (D-recipient) test, offline end-to-end:
//
//   1. Simulate the on-chain side: a real transfer witness produces the event
//      fields (R_e, sigma, v_tilde) exactly as the contract would emit them.
//   2. Holder side: build the disclosure witness, prove with the shared
//      committed disclosure artifact (UltraHonk, keccak transcript).
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

import { deriveKeys } from "../src/crypto/keys.ts";
import { addressToField } from "../src/crypto/address.ts";
import { randomScalar, toHex32, fromHex } from "../src/crypto/field.ts";
import { pointCoords } from "../src/crypto/grumpkin.ts";
import { G, scalarMul } from "../src/crypto/grumpkin.ts";
import { buildTransferWitness } from "../src/witness/transfer.ts";
import { CircuitProver } from "../src/proving/prover.ts";
import {
  generateRecipientKeys,
  newDisclosureRequest,
  decryptDisclosure,
  pointFromJson,
} from "../src/disclosure/recipient.ts";
import { buildDiscloseRecipientWitness } from "../src/witness/disclose-recipient.ts";
import { buildDiscloseSenderWitness } from "../src/witness/disclose-sender.ts";

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

const prover = new CircuitProver(circuit);
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

await prover.destroy();

// --- 5. D-sender: the originator proves the same event from their side ------
console.log("\nD-sender:");
const senderReceiver = generateRecipientKeys();
const senderRequest = newDisclosureRequest(senderReceiver);

// The retained scalar must match the event's R_e — a stale one is rejected
// before proving.
let threw = false;
try {
  buildDiscloseSenderWitness({
    keys: sender,
    rEScalar: randomScalar(),
    event,
    pvkB: holder.PVK,
    pR: pointFromJson(senderRequest.pR),
    nu: fromHex(senderRequest.nu),
  });
} catch {
  threw = true;
}
check(threw, "witness builder rejects a stale/mismatched retained r_e");

const sw = buildDiscloseSenderWitness({
  keys: sender,
  rEScalar: tw.rEScalar,
  event,
  pvkB: holder.PVK,
  pR: pointFromJson(senderRequest.pR),
  nu: fromHex(senderRequest.nu),
});
check(sw.vTx === AMOUNT, `sender witness reconstructs the event amount (${sw.vTx})`);

const senderProver = new CircuitProver(senderCircuit);
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
console.log(`\ndisclosure: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
