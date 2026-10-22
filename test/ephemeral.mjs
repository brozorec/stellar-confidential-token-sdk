// Fast deterministic-r_e checks (no proving): the transfer witness derives
// r_e = Poseidon2(EPHEMERAL_KEY, vk, sigma) by default, so the sender can
// re-derive it from the event's public fields alone and build a D-sender
// disclosure with no retained state. Random override must keep working, and
// the recipient/auditor channels must be unaffected.
import { deriveKeys } from "../src/crypto/keys.ts";
import { H, scalarMul, ecdh } from "../src/crypto/grumpkin.ts";
import { DOMAIN } from "../src/crypto/constants.ts";
import { deriveEphemeralRE, decryptWithDomain } from "../src/crypto/poseidon2.ts";
import { buildTransferWitness } from "../src/witness/transfer.ts";
import { buildWithdrawWitness } from "../src/witness/withdraw.ts";
import {
  buildDiscloseSenderWitness,
  senderEphemeralScalar,
  NotDisclosableError,
} from "../src/witness/disclose-sender.ts";
import { proveSenderDisclosure } from "../src/disclosure/prove.ts";
import { auditTransfer, auditorPublicKey } from "../src/auditor/decrypt.ts";

let pass = 0, fail = 0;
const ok = (cond, msg) => { if (cond) { pass++; } else { fail++; console.error("  ✗ " + msg); } };

const addrF = 0x1234n;
const sender = deriveKeys(1111n, addrF);
const recipient = deriveKeys(2222n, addrF);
const kAud = auditorPublicKey(42n);
const v = 1_000_000n, r = 777n, amount = 123_456n;

const tw = buildTransferWitness({
  keys: sender, v, r, amount,
  pvkB: recipient.PVK, kAudR: kAud, kAudS: kAud,
});

// Default r_e is the deterministic derivation, and R_e matches it.
ok(tw.rEScalar === deriveEphemeralRE(sender.vk, tw.payload.sigma), "default r_e == Poseidon2(EPHEMERAL_KEY, vk, sigma)");
ok(scalarMul(tw.rEScalar, H).equals(tw.payload.rE), "R_e == derived r_e · H");
ok(tw.rEScalar !== 0n, "derived r_e nonzero (T8)");

// Sender-side recovery from event fields alone (vk + public sigma + R_e).
const recovered = deriveEphemeralRE(sender.vk, tw.payload.sigma);
ok(scalarMul(recovered, H).equals(tw.payload.rE), "recovered scalar reproduces the event's R_e");

// D-sender witness re-derives the scalar itself — no retention involved.
const event = { rE: tw.payload.rE, sigma: tw.payload.sigma, vTilde: tw.payload.vTilde };
ok(senderEphemeralScalar(sender, event) === recovered, "disclosability check returns the derived r_e");
const ds = buildDiscloseSenderWitness({
  keys: sender,
  event,
  pvkB: recipient.PVK,
  pR: scalarMul(99n, H),
  nu: 0xabcn,
});
ok(ds.vTx === amount, "D-sender from re-derived r_e discloses the right amount");
ok(ds.inputs.r_e === "0x" + recovered.toString(16).padStart(64, "0"), "witness carries the derived r_e");

// Determinism + per-sigma uniqueness.
ok(deriveEphemeralRE(sender.vk, tw.payload.sigma) === tw.rEScalar, "derivation is deterministic");
ok(deriveEphemeralRE(sender.vk, tw.payload.sigma + 1n) !== tw.rEScalar, "fresh sigma -> fresh r_e");
ok(deriveEphemeralRE(recipient.vk, tw.payload.sigma) !== tw.rEScalar, "different vk -> different r_e");

// Recipient decryption and auditor channels are unaffected by derived r_e.
const sB = ecdh(recipient.vk, tw.payload.rE);
ok(
  decryptWithDomain(tw.payload.vTilde, DOMAIN.TRANSFER_AMOUNT, sB, tw.payload.sigma) === amount,
  "recipient still decrypts v_transfer",
);
const audited = auditTransfer(42n, { ...tw.payload });
ok(audited.amount === amount && audited.channelsAgree, "auditor channels still decrypt");

// Explicit random override is still honored (legacy behavior).
const twRand = buildTransferWitness({
  keys: sender, v, r, amount,
  pvkB: recipient.PVK, kAudR: kAud, kAudS: kAud,
  rE: 31337n,
});
ok(twRand.rEScalar === 31337n, "explicit p.rE override respected");
ok(scalarMul(31337n, H).equals(twRand.payload.rE), "override R_e consistent");

// ...but such a transfer is NOT disclosable by its sender, and that is a typed
// outcome, not a proving error (docs/sdk/clients.md#disclosure-construction).
const randEvent = { rE: twRand.payload.rE, sigma: twRand.payload.sigma, vTilde: twRand.payload.vTilde };
ok(senderEphemeralScalar(sender, randEvent) === null, "override r_e: not disclosable");
ok(senderEphemeralScalar(recipient, event) === null, "non-originator keys: not disclosable");
let caught;
try {
  buildDiscloseSenderWitness({ keys: sender, event: randEvent, pvkB: recipient.PVK, pR: scalarMul(99n, H), nu: 1n });
} catch (e) {
  caught = e;
}
ok(caught instanceof NotDisclosableError && caught.reason === "ephemeral-scalar-mismatch", "builder throws NotDisclosableError");
// proveSenderDisclosure returns the outcome before it ever touches the prover.
let proverTouched = false;
const stubProver = { zk: true, prove: async () => { proverTouched = true; throw new Error("unreachable"); } };
const outcome = await proveSenderDisclosure({
  keys: sender,
  event: { ...randEvent, id: "x", ledger: 1, txHash: "00", type: "transfer" },
  pvkB: recipient.PVK,
  request: { pR: { x: "0x" + "0".repeat(63) + "1", y: "0x" + "0".repeat(63) + "2" }, nu: "0x01" },
  prover: stubProver,
});
ok(outcome.disclosable === false && outcome.reason === "ephemeral-scalar-mismatch" && !("bundle" in outcome),
  "proveSenderDisclosure: { disclosable: false } with no proof and no amount");
ok(!proverTouched, "not-disclosable outcome never reaches the prover");
let zkErr;
try {
  await proveSenderDisclosure({ keys: sender, event: { ...event, id: "x", ledger: 1, txHash: "00", type: "transfer" },
    pvkB: recipient.PVK, request: { pR: { x: "0x01", y: "0x02" }, nu: "0x01" }, prover: { zk: false } });
} catch (e) {
  zkErr = e;
}
ok(zkErr && /zk: true/.test(zkErr.message), "disclosure proving refuses a non-ZK prover");

// Withdraw derives r_e the same way (keys-and-commitments.md#ecdh-derived-blinding:
// "Transfer, Withdraw, and SetSpender from the owner's viewing key").
const ww = buildWithdrawWitness({ keys: sender, v, r, amount: 400n, kAudS: kAud });
ok(
  scalarMul(deriveEphemeralRE(sender.vk, ww.payload.sigma), H).equals(ww.payload.rE),
  "withdraw default R_e == Poseidon2(EPHEMERAL_KEY, vk, sigma) · H",
);
const wwRand = buildWithdrawWitness({ keys: sender, v, r, amount: 400n, kAudS: kAud, rE: 31337n });
ok(scalarMul(31337n, H).equals(wwRand.payload.rE), "withdraw explicit p.rE override respected");

// Only the zero derivation maps to "not disclosable"; a malformed key or
// sigma is a caller bug and must surface, not read as a disclosure outcome.
const throwsTypeError = (fn) => {
  try {
    fn();
    return false;
  } catch (e) {
    return e instanceof TypeError;
  }
};
ok(
  throwsTypeError(() => senderEphemeralScalar({ ...sender, vk: undefined }, { rE: tw.payload.rE, sigma: tw.payload.sigma })),
  "senderEphemeralScalar: missing vk throws, not null",
);
ok(
  throwsTypeError(() => senderEphemeralScalar(sender, { rE: tw.payload.rE, sigma: undefined })),
  "senderEphemeralScalar: missing sigma throws, not null",
);

console.log(`\nephemeral: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
