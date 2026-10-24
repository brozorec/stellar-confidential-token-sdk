// Fast auditor-decryption round-trip (no proving): build transfer/withdraw
// witnesses with a known auditor secret k (K_aud = k·H), then check that the
// auditor-side decryptors recover the amount, the sender's post-op balance,
// and r_transfer from nothing but the would-be event fields and k.
import { deriveKeys } from "../src/crypto/keys.ts";
import { H, scalarMul, commit } from "../src/crypto/grumpkin.ts";
import { buildTransferWitness } from "../src/witness/transfer.ts";
import { buildWithdrawWitness } from "../src/witness/withdraw.ts";
import { buildSetSpenderWitness } from "../src/witness/set-spender.ts";
import { buildSpenderTransferWitness } from "../src/witness/spender-transfer.ts";
import {
  auditSetSpender,
  auditSpenderTransfer,
  auditSpenderTransferOwnerChannel,
  auditSpenderTransferRecipientChannel,
  auditTransfer,
  auditTransferSenderChannel,
  auditTransferRecipientChannel,
  auditWithdraw,
  auditorPublicKey,
} from "../src/auditor/decrypt.ts";

let pass = 0, fail = 0;
const ok = (cond, msg) => { if (cond) { pass++; } else { fail++; console.error("  ✗ " + msg); } };

const addrF = 0x1234n;
const sender = deriveKeys(1111n, addrF);
const recipient = deriveKeys(2222n, addrF);
const k = 0x00c066da47bac8f87cd3eb9a36c37b417ca40cfa2730e7d8eb7f0bf939d11832n;
const kAud = auditorPublicKey(k);
ok(kAud.equals(scalarMul(k, H)), "auditorPublicKey == k·H");

// --- transfer: both channels under a single auditor key --------------------
const v = 1_000_000n, r = 777n, amount = 123_456n;
const tw = buildTransferWitness({
  keys: sender, v, r, amount,
  pvkB: recipient.PVK, kAudR: kAud, kAudS: kAud,
});
// Project the payload into the event shape the auditor sees on-chain.
const tev = {
  rE: tw.payload.rE, sigma: tw.payload.sigma,
  vAudR: tw.payload.vAudR, rAudR: tw.payload.rAudR,
  vAudS: tw.payload.vAudS, bAudS: tw.payload.bAudS, rAudS: tw.payload.rAudS,
};

const audited = auditTransfer(k, tev);
ok(audited.amount === amount, "transfer: amount recovered");
ok(audited.senderBalance === v - amount, "transfer: sender post-balance recovered");
ok(audited.senderBlinding === tw.next.r, "transfer: sender post-blinding recovered (lane 2)");
// The sender channel is now a full opening of the sender's new C_spend.
ok(
  commit(audited.senderBalance, audited.senderBlinding).equals(tw.payload.cSpendNew),
  "transfer: (senderBalance, senderBlinding) opens C_spend'",
);
ok(audited.channelsAgree, "transfer: both channels agree");
// r_transfer must open the emitted C_transfer: commit(v_transfer, r_transfer) == C_transfer.
ok(
  commit(audited.amount, audited.rTransfer).equals(tw.payload.cTransfer),
  "transfer: (v_transfer, r_transfer) opens C_transfer",
);

const sCh = auditTransferSenderChannel(k, tev);
const rCh = auditTransferRecipientChannel(k, tev);
ok(sCh.amount === amount && sCh.senderBalance === v - amount, "sender channel standalone");
ok(rCh.amount === amount && rCh.rTransfer === audited.rTransfer, "recipient channel standalone");

// Wrong key: decrypts to garbage and the channels disagree.
const wrong = auditTransfer(k + 1n, tev);
ok(!wrong.channelsAgree, "wrong key: channels disagree");
ok(wrong.amount !== amount, "wrong key: amount not recovered");

// --- withdraw: sender-channel balance checkpoint ----------------------------
const ww = buildWithdrawWitness({ keys: sender, v, r, amount: 400n, kAudS: kAud });
const wAudited = auditWithdraw(k, {
  rE: ww.payload.rE, sigma: ww.payload.sigma, bAudS: ww.payload.bAudS, rAudS: ww.payload.rAudS,
});
ok(wAudited.senderBalance === v - 400n, "withdraw: post-balance recovered");
ok(wAudited.senderBlinding === ww.next.r, "withdraw: post-blinding recovered (lane 2)");
ok(
  commit(wAudited.senderBalance, wAudited.senderBlinding).equals(ww.payload.cSpendNew),
  "withdraw: (senderBalance, senderBlinding) opens C_spend'",
);

// --- set_spender: owner channel + the r_a escrow (tag 17 over op_i) ---------
const SPENDER = "GBPRIMWXMQQZGAP5YJLHTFSOLAOEYKUAJYH4A7ORYAAVIVBHTRWYZWFH";
const spenderKeys = deriveKeys(3333n, addrF);
const VA = 250_000n;
const sw = buildSetSpenderWitness({
  keys: sender, v, r, amount: VA, spender: SPENDER, yOp: spenderKeys.Y, kAudS: kAud,
});
const sev = {
  spender: SPENDER, rE: sw.payload.rE, sigma: sw.payload.sigma, vAudS: sw.payload.vAudS,
  bAudS: sw.payload.bAudS, rAudS: sw.payload.rAudS, raAudS: sw.payload.raAudS,
};
const sAudited = auditSetSpender(k, sev);
ok(sAudited.amount === VA, "set_spender: escrowed amount recovered (lane 0)");
ok(
  commit(sAudited.senderBalance, sAudited.senderBlinding).equals(sw.payload.cSpendNew),
  "set_spender: (senderBalance, senderBlinding) opens the owner's C_spend'",
);
ok(
  commit(sAudited.amount, sAudited.allowanceBlinding).equals(sw.payload.cA),
  "set_spender: (amount, allowanceBlinding) opens C_a — from the event alone",
);
// op_i comes from the event's spender topic: another spender opens nothing.
const otherSpender = auditSetSpender(k, { ...sev, spender: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN" });
ok(otherSpender.allowanceBlinding !== sw.allowance.r, "set_spender: wrong spender topic does not recover r_a");

// --- spender_transfer: both channels keyed by σ_a', owner channel = C_a' ----
const SPENT = 100_000n;
const stw = buildSpenderTransferWitness({
  keys: spenderKeys,
  allowance: { dvk: sw.allowance.dvk, sigmaA: sw.allowance.sigmaA, v: VA },
  amount: SPENT,
  pvkRecipient: recipient.PVK,
  kAudR: kAud,
  kAudS: kAud,
});
const stev = {
  type: "spender_transfer",
  rE: stw.payload.rE, sigmaANew: stw.payload.sigmaANew,
  vAudR: stw.payload.vAudR, rAudR: stw.payload.rAudR,
  vAudS: stw.payload.vAudS, aAudS: stw.payload.aAudS, rAudS: stw.payload.rAudS,
};
const stAudited = auditSpenderTransfer(k, stev);
ok(stAudited.amount === SPENT && stAudited.channelsAgree, "spender_transfer: amount + channel agreement");
ok(stAudited.allowance === VA - SPENT, "spender_transfer: post-transfer allowance recovered (lane 1)");
ok(
  commit(stAudited.allowance, stAudited.allowanceBlinding).equals(stw.payload.cANew),
  "spender_transfer: (allowance, allowanceBlinding) opens C_a'",
);
ok(
  commit(stAudited.amount, stAudited.rTransfer).equals(stw.payload.cTransfer),
  "spender_transfer: (amount, rTransfer) opens C_transfer",
);
ok(
  auditSpenderTransferOwnerChannel(k, stev).allowance === VA - SPENT &&
    auditSpenderTransferRecipientChannel(k, stev).rTransfer === stw.recipientView.rTransfer,
  "spender_transfer: channels standalone",
);
// The pads are keyed by σ_a'; decrypting under the consumed σ_a yields garbage.
ok(
  auditSpenderTransfer(k, { ...stev, sigmaANew: sw.allowance.sigmaA }).amount !== SPENT,
  "spender_transfer: the consumed salt does not decrypt",
);
ok(!auditSpenderTransfer(k + 1n, stev).channelsAgree, "spender_transfer: wrong key → channels disagree");

console.log(`\nauditor: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
