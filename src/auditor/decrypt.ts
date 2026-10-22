/**
 * Auditor-side event decryption.
 *
 * The auditor holds the Grumpkin secret `k` behind the registry key
 * `K_aud = k·H` and decrypts the auditor ciphertexts every withdraw/transfer
 * event carries — using nothing but the public event and `k`. No viewing
 * keys, no holder cooperation, no extra on-chain data:
 *
 *   s     = ecdh(k, R_e)             (ECDH against the event's ephemeral point;
 *                                     equals the prover's ecdh(r_e, K_aud))
 *   masks = SpongeSqueeze3(δ_aud_s, s, σ)   sender channel, three lanes
 *         | SpongeSqueeze2(δ_aud_r, s, σ)   recipient channel, two lanes
 *   plaintext = ciphertext − mask
 *
 * Channels:
 *   - sender channel (δ_aud_s):    transfer amount + sender's post-op balance
 *     + sender's post-op spendable blinding r' (lane 2) — together a full
 *     opening of the sender's new C_spend
 *   - recipient channel (δ_aud_r): transfer amount + per-transfer Pedersen
 *     randomness r_transfer (a full opening of C_transfer, hence of the
 *     recipient's receiving balance between merges)
 *
 * Withdraw events carry only the sender channel's checkpoint lanes: lane 1
 * (post-op balance) and lane 2 (post-op blinding). Lane 0, the amount slot,
 * goes unused because the withdrawn amount is public.
 */

import { H, ecdh, scalarMul, type Point } from "../crypto/grumpkin.js";
import { frMod } from "../crypto/field.js";
import { DOMAIN } from "../crypto/constants.js";
import { spongeSqueeze2, spongeSqueeze3 } from "../crypto/poseidon2.js";
import type { TransferEvent, WithdrawEvent } from "../chain/events.js";

/** What the sender's auditor learns from one transfer (T_a5–T_a9). */
export interface AuditedSenderChannel {
  /** Transfer amount `v_transfer`. */
  amount: bigint;
  /** Sender's post-transfer spendable balance `v_A − v_transfer`. */
  senderBalance: bigint;
  /**
   * Sender's post-transfer spendable blinding `r_A'` — with `senderBalance`, a
   * full opening of the sender's new `C_spend`.
   */
  senderBlinding: bigint;
}

/** What the recipient's auditor learns from one transfer (T_a1–T_a4). */
export interface AuditedRecipientChannel {
  /** Transfer amount `v_transfer`. */
  amount: bigint;
  /**
   * Per-transfer Pedersen randomness `r_transfer` — with `amount`, a full
   * opening of `C_transfer`.
   */
  rTransfer: bigint;
}

/** Decrypt a transfer's sender-auditor channel with the auditor secret `k`. */
export function auditTransferSenderChannel(
  k: bigint,
  ev: Pick<TransferEvent, "rE" | "sigma" | "vAudS" | "bAudS" | "rAudS">,
): AuditedSenderChannel {
  const sX = ecdh(k, ev.rE);
  const [mV, mB, mR] = spongeSqueeze3(DOMAIN.AUDITOR_SENDER, sX, ev.sigma);
  return {
    amount: frMod(ev.vAudS - mV),
    senderBalance: frMod(ev.bAudS - mB),
    senderBlinding: frMod(ev.rAudS - mR),
  };
}

/** Decrypt a transfer's recipient-auditor channel with the auditor secret `k`. */
export function auditTransferRecipientChannel(
  k: bigint,
  ev: Pick<TransferEvent, "rE" | "sigma" | "vAudR" | "rAudR">,
): AuditedRecipientChannel {
  const sX = ecdh(k, ev.rE);
  const [mV, mR] = spongeSqueeze2(DOMAIN.AUDITOR_RECIPIENT, sX, ev.sigma);
  return { amount: frMod(ev.vAudR - mV), rTransfer: frMod(ev.rAudR - mR) };
}

/** Both channels of one transfer, decrypted under a single auditor key. */
export interface AuditedTransfer {
  /** Transfer amount `v_transfer` (from the sender channel). */
  amount: bigint;
  /** Sender's post-transfer spendable balance. */
  senderBalance: bigint;
  /** Sender's post-transfer spendable blinding (sender channel, lane 2). */
  senderBlinding: bigint;
  /** Per-transfer Pedersen randomness (recipient channel). */
  rTransfer: bigint;
  /**
   * The amount decrypts independently on each channel; under the correct key
   * the two MUST agree (the circuit constrains both to the same `v_transfer`).
   * `false` means `k` is not the auditor key for both parties of this event.
   */
  channelsAgree: boolean;
}

/**
 * Decrypt everything a transfer reveals to an auditor holding `k` for BOTH
 * the sender's and the recipient's `auditor_id` — the single-auditor setup
 * where every account registers under auditor id 0.
 */
export function auditTransfer(k: bigint, ev: TransferEvent): AuditedTransfer {
  const s = auditTransferSenderChannel(k, ev);
  const r = auditTransferRecipientChannel(k, ev);
  return {
    amount: s.amount,
    senderBalance: s.senderBalance,
    senderBlinding: s.senderBlinding,
    rTransfer: r.rTransfer,
    channelsAgree: s.amount === r.amount,
  };
}

/**
 * Decrypt a withdraw's sender-auditor checkpoint: the post-withdrawal
 * spendable balance `v − a` and blinding `r'`, a full opening of the new
 * `C_spend`. The amount itself is public in the event.
 *
 * The pads are lanes 1 and 2 of `sponge_squeeze_3(δ_aud_s, s, σ)` — the same
 * lanes the transfer sender channel uses (W_a3–W_a5). Lane 0, the amount slot,
 * is deliberately skipped.
 */
export function auditWithdraw(
  k: bigint,
  ev: Pick<WithdrawEvent, "rE" | "sigma" | "bAudS" | "rAudS">,
): { senderBalance: bigint; senderBlinding: bigint } {
  const sX = ecdh(k, ev.rE);
  const [, mB, mR] = spongeSqueeze3(DOMAIN.AUDITOR_SENDER, sX, ev.sigma);
  return { senderBalance: frMod(ev.bAudS - mB), senderBlinding: frMod(ev.rAudS - mR) };
}

/** The registry public key `K_aud = k·H` for an auditor secret `k`. */
export function auditorPublicKey(k: bigint): Point {
  return scalarMul(k, H);
}
