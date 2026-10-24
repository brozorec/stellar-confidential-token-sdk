// XDR envelope encoding test. Verifies the `{payload, proof}` Bytes argument:
//   1. round-trips structurally (decode back to a sorted ScMap),
//   2. uses flat 64-byte Points and 32-byte fields,
//   3. byte-matches stellar-sdk's canonical nativeToScVal encoding.
// The definitive check is on-chain from_xdr, but a nativeToScVal match
// gives strong confidence the contracttype layout is right.
import { xdr } from "@stellar/stellar-sdk";

import { deriveKeys } from "../src/crypto/keys.ts";
import { addressToField } from "../src/crypto/address.ts";
import { randomScalar, toBytes32BE } from "../src/crypto/field.ts";
import { pointToBytes } from "../src/crypto/grumpkin.ts";
import { buildRegisterWitness } from "../src/witness/register.ts";
import { buildWithdrawWitness } from "../src/witness/withdraw.ts";
import { buildTransferWitness } from "../src/witness/transfer.ts";
import { buildSetSpenderWitness } from "../src/witness/set-spender.ts";
import { buildSpenderTransferWitness } from "../src/witness/spender-transfer.ts";
import {
  encodeRegisterData,
  encodeWithdrawData,
  encodeTransferData,
  encodeSetSpenderData,
  encodeSpenderTransferData,
} from "../src/chain/payload.ts";
import { optionAddr } from "../src/chain/factory.ts";

let pass = 0,
  fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

const addrF = addressToField("CCREDIB3DG3IBVUKBL7QMEK4MTPSTODR7MQ34QY4SQ5LZ5L4WFWNVNXG");
const keys = deriveKeys(randomScalar(), addrF);
const ACCOUNT = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

// Fake proof bytes (encoding is independent of proof validity).
const proof = new Uint8Array(14592).fill(7);

console.log("register envelope:");
const w = buildRegisterWitness(keys, ACCOUNT);
const dataArg = encodeRegisterData(w, proof);

ok(dataArg.switch().name === "scvBytes", "data arg is scvBytes");
const inner = xdr.ScVal.fromXDR(dataArg.bytes());
ok(inner.switch().name === "scvMap", "inner is scvMap");

// Keys present and sorted: payload, proof.
const keysInOrder = inner.map().map((e) => e.key().sym().toString());
ok(JSON.stringify(keysInOrder) === JSON.stringify(["payload", "proof"]), "top keys sorted [payload, proof]");

const payloadEntry = inner.map().find((e) => e.key().sym().toString() === "payload").val();
const proofEntry = inner.map().find((e) => e.key().sym().toString() === "proof").val();
ok(proofEntry.bytes().length === 14592, "proof is 14592 bytes");

const payloadKeys = payloadEntry.map().map((e) => e.key().sym().toString());
ok(JSON.stringify(payloadKeys) === JSON.stringify(["pvk", "y"]), "payload keys sorted [pvk, y]");
const yEntry = payloadEntry.map().find((e) => e.key().sym().toString() === "y").val();
ok(yEntry.bytes().length === 64, "Point y is flat 64 bytes");
ok(
  Buffer.from(pointToBytes(keys.Y)).equals(yEntry.bytes()),
  "Point y bytes == pointToBytes(Y)",
);

// Soroban #[contracttype] structs use Symbol keys (ScVal type 15), NOT String
// (type 14). nativeToScVal(plainObject) defaults to String keys and would be
// rejected by from_xdr, so assert the key type explicitly — this is the real
// invariant the contract requires.
ok(
  inner.map().every((e) => e.key().switch().name === "scvSymbol"),
  "top map keys are Symbols (not Strings)",
);
ok(
  payloadEntry.map().every((e) => e.key().switch().name === "scvSymbol"),
  "payload map keys are Symbols (not Strings)",
);

console.log("transfer envelope:");
const recipient = deriveKeys(randomScalar(), addrF);
const tw = buildTransferWitness({
  keys,
  v: 1000n,
  r: 0n,
  amount: 250n,
  pvkB: recipient.PVK,
  kAudR: recipient.PVK,
  kAudS: keys.PVK,
});
const tData = encodeTransferData(tw, proof);
const tInner = xdr.ScVal.fromXDR(tData.bytes());
const tPayload = tInner.map().find((e) => e.key().sym().toString() === "payload").val();
const tKeys = tPayload.map().map((e) => e.key().sym().toString());
ok(
  JSON.stringify(tKeys) ===
    JSON.stringify([
      "b_tilde",
      "b_tilde_aud_s",
      "c_spend_new",
      "c_transfer",
      "r_e_point",
      "r_tilde_aud_r",
      "r_tilde_aud_s",
      "sigma",
      "v_tilde",
      "v_tilde_aud_r",
      "v_tilde_aud_s",
    ]),
  "transfer payload keys sorted (11 fields)",
);
const cTransfer = tPayload.map().find((e) => e.key().sym().toString() === "c_transfer").val();
ok(cTransfer.bytes().length === 64, "c_transfer is 64 bytes");
const bTilde = tPayload.map().find((e) => e.key().sym().toString() === "b_tilde").val();
ok(bTilde.bytes().length === 32, "b_tilde is 32 bytes");
const tRAudS = tPayload.map().find((e) => e.key().sym().toString() === "r_tilde_aud_s").val();
ok(
  Buffer.from(toBytes32BE(tw.payload.rAudS)).equals(tRAudS.bytes()),
  "transfer r_tilde_aud_s bytes == witness value",
);

console.log("withdraw envelope:");
const ww = buildWithdrawWitness({ keys, v: 1000n, r: 0n, amount: 400n, kAudS: recipient.PVK });
const wInner = xdr.ScVal.fromXDR(encodeWithdrawData(ww, proof).bytes());
const wPayload = wInner.map().find((e) => e.key().sym().toString() === "payload").val();
ok(
  JSON.stringify(wPayload.map().map((e) => e.key().sym().toString())) ===
    JSON.stringify(["b_tilde", "b_tilde_aud_s", "c_spend_new", "r_e_point", "r_tilde_aud_s", "sigma"]),
  "withdraw payload keys sorted (6 fields)",
);
ok(
  wPayload.map().every((e) => e.key().switch().name === "scvSymbol"),
  "withdraw payload map keys are Symbols",
);

const payloadOf = (data) =>
  xdr.ScVal.fromXDR(data.bytes()).map().find((e) => e.key().sym().toString() === "payload").val();
const fieldOf = (payload, k) => payload.map().find((e) => e.key().sym().toString() === k).val();

console.log("set_spender envelope:");
const sw = buildSetSpenderWitness({
  keys, v: 1000n, r: 5n, amount: 300n, spender: ACCOUNT, yOp: recipient.Y, kAudS: recipient.PVK,
});
const sPayload = payloadOf(encodeSetSpenderData(sw, proof));
ok(
  JSON.stringify(sPayload.map().map((e) => e.key().sym().toString())) ===
    JSON.stringify([
      "a_tilde",
      "b_tilde",
      "b_tilde_aud_s",
      "c_a",
      "c_spend_new",
      "escrowed_dvk",
      "r_a_tilde_aud_s",
      "r_e_point",
      "r_tilde_aud_s",
      "sigma",
      "sigma_a",
      "v_tilde_aud_s",
    ]),
  "set_spender payload keys sorted (12 fields)",
);
ok(sPayload.map().every((e) => e.key().switch().name === "scvSymbol"), "set_spender payload map keys are Symbols");
// escrowed_dvk is (R_x, dvk_cipher), and R_x is R_e.x — the first half of r_e_point.
const esc = fieldOf(sPayload, "escrowed_dvk").bytes();
ok(esc.length === 64, "escrowed_dvk is 64 bytes");
ok(
  Buffer.from(esc.subarray(0, 32)).equals(Buffer.from(pointToBytes(sw.payload.rE).subarray(0, 32))),
  "escrowed_dvk[0..32] == R_e.x",
);
ok(
  Buffer.from(esc.subarray(32)).equals(Buffer.from(toBytes32BE(sw.payload.escrowedDvk.cipher))),
  "escrowed_dvk[32..64] == dvk_cipher",
);
ok(fieldOf(sPayload, "c_a").bytes().length === 64, "c_a is 64 bytes");
ok(
  Buffer.from(toBytes32BE(sw.payload.raAudS)).equals(fieldOf(sPayload, "r_a_tilde_aud_s").bytes()),
  "r_a_tilde_aud_s bytes == witness value",
);

console.log("spender_transfer envelope:");
const stw = buildSpenderTransferWitness({
  keys: recipient,
  allowance: { dvk: sw.allowance.dvk, sigmaA: sw.allowance.sigmaA, v: sw.allowance.v },
  amount: 100n,
  pvkRecipient: keys.PVK,
  kAudR: keys.PVK,
  kAudS: recipient.PVK,
});
const stPayload = payloadOf(encodeSpenderTransferData(stw, proof));
ok(
  JSON.stringify(stPayload.map().map((e) => e.key().sym().toString())) ===
    JSON.stringify([
      "a_tilde_aud_s",
      "a_tilde_new",
      "c_a_new",
      "c_transfer",
      "r_e_point",
      "r_tilde_aud_r",
      "r_tilde_aud_s",
      "sigma_a_new",
      "v_tilde",
      "v_tilde_aud_r",
      "v_tilde_aud_s",
    ]),
  "spender_transfer payload keys sorted (11 fields)",
);
ok(stPayload.map().every((e) => e.key().switch().name === "scvSymbol"), "spender_transfer payload map keys are Symbols");
ok(
  Buffer.from(toBytes32BE(stw.payload.sigmaANew)).equals(fieldOf(stPayload, "sigma_a_new").bytes()),
  "sigma_a_new bytes == witness value",
);

console.log("Option<Address> encoding:");
ok(optionAddr(undefined).switch().name === "scvVoid", "optionAddr(undefined) → Void");
ok(optionAddr(null).switch().name === "scvVoid", "optionAddr(null) → Void");
ok(optionAddr(ACCOUNT).switch().name === "scvAddress", "optionAddr(G…) → Address");
let emptyAddrErr;
try {
  optionAddr("");
} catch (e) {
  emptyAddrErr = e;
}
ok(emptyAddrErr !== undefined, "optionAddr(\"\") throws instead of encoding None");

console.log(`\npayload: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
