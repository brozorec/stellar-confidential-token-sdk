/**
 * SpenderTransfer-circuit witness (`confidential_transfer_from`). A spender
 * moves `amount` out of an owner's allowance `C_a` into the recipient's
 * receiving balance, re-commits the remainder as `C_a'`, and emits the
 * recipient-auditor channel plus the OWNER-auditor channel.
 *
 * Every pad, and the ephemeral scalar, is keyed by the fresh replacement salt
 * `σ_a'`; the stored `σ_a` only opens the current allowance (O3). The circuit
 * does not constrain `vk`: contract binding comes through `C_a` (O2/O3).
 *
 * Public-input order (25 fields, matches `storage.rs::confidential_transfer_from`):
 *   C_a, sigma_a, Y_op, PVK_recipient, K_aud_r, K_aud_s, C_a', C_transfer,
 *   R_e, v_tilde, a_tilde', sigma_a', v_tilde_aud_r, r_tilde_aud_r,
 *   v_tilde_aud_s, a_tilde_aud_s, r_tilde_aud_s
 */

import type { KeyPair } from "../crypto/keys.js";
import { H, commit, scalarMul, ecdh, type Point } from "../crypto/grumpkin.js";
import { randomScalar, frAdd } from "../crypto/field.js";
import { DOMAIN } from "../crypto/constants.js";
import {
  deriveAllowR,
  deriveEphemeralRE,
  deriveTransferBlind,
  encryptAllowance,
  encryptAmount,
  encryptAuditorSender,
  spongeSqueeze2,
} from "../crypto/poseidon2.js";
import { fieldIn, pointIn, type NoirInputs } from "./common.js";

export interface SpenderTransferParams {
  /** Spender's contract-bound key set (`sk_op`, and `vk_op` for `r_e`). */
  keys: KeyPair;
  /**
   * The delegation's current state: its key `dvk`, stored salt `σ_a`, and
   * allowance value `v_a`. Take it from `SpenderWallet.allowanceForProof()`,
   * which recovers `dvk` from the on-chain escrow and checks the opening
   * against `C_a`; this builder does not (`r_a` is re-derived from `dvk, σ_a`).
   */
  allowance: { dvk: bigint; sigmaA: bigint; v: bigint };
  /** Transfer amount `v_transfer` (0 ≤ v_transfer ≤ v_a). */
  amount: bigint;
  /** Recipient's public viewing key (its account's `viewing_public_key`). */
  pvkRecipient: Point;
  /** Recipient's auditor key `K_aud_r`. */
  kAudR: Point;
  /** The OWNER's auditor key `K_aud_s` (not the spender's). */
  kAudS: Point;
  /**
   * Replacement allowance salt `σ_a'` (defaults to a fresh random scalar).
   * MUST be fresh per attempt and never repeat over the delegation's life
   * (docs/sdk/wallet.md#salt-freshness); the circuit only rejects `σ_a' = σ_a`.
   */
  sigmaANew?: bigint;
  /**
   * Optional fixed ephemeral scalar `r_e ≠ 0`. Defaults to
   * `Poseidon2(EPHEMERAL_KEY, vk_op, σ_a')` from the SPENDER's own viewing
   * key, which is what lets the spender D-sender this transfer later.
   */
  rE?: bigint;
}

export interface SpenderTransferWitness {
  inputs: NoirInputs;
  /** On-chain `SpenderTransferPayload`. `rE` is the POINT `R_e = r_e·H`. */
  payload: {
    cANew: Point;
    cTransfer: Point;
    rE: Point;
    vTilde: bigint;
    aTildeNew: bigint;
    sigmaANew: bigint;
    vAudR: bigint;
    rAudR: bigint;
    vAudS: bigint;
    aAudS: bigint;
    rAudS: bigint;
  };
  /** The delegation's post-transfer allowance, as the contract stores it. */
  next: { v: bigint; r: bigint; cA: Point; sigmaA: bigint; aTilde: bigint };
  /** What the recipient recovers from the event; exposed for tests. */
  recipientView: { vTransfer: bigint; rTransfer: bigint; cTransfer: Point };
  /** The ephemeral SCALAR `r_e`, for inspection and tests. */
  rEScalar: bigint;
}

export function buildSpenderTransferWitness(p: SpenderTransferParams): SpenderTransferWitness {
  const { keys, allowance, amount, pvkRecipient, kAudR, kAudS } = p;
  const { dvk, sigmaA, v: vA } = allowance;
  if (amount < 0n) throw new Error("transfer amount must be non-negative");
  const vANew = vA - amount;
  if (vANew < 0n) throw new Error("transfer amount exceeds the allowance");

  // O14: the replacement salt must differ from the stored one.
  if (p.sigmaANew !== undefined && p.sigmaANew === sigmaA) {
    throw new Error("sigmaANew must differ from the delegation's current salt (O14)");
  }
  let sigmaANew = p.sigmaANew ?? randomScalar();
  while (sigmaANew === sigmaA) sigmaANew = randomScalar();
  const rE = p.rE ?? deriveEphemeralRE(keys.vk, sigmaANew);

  // Current allowance (O2, O3).
  const rA = deriveAllowR(dvk, sigmaA);
  const cA = commit(vA, rA);
  const rePoint = scalarMul(rE, H);

  // Recipient ECDH → transfer commitment + encrypted amount (O5–O9).
  const sX = ecdh(rE, pvkRecipient);
  const rTransfer = deriveTransferBlind(sX, sigmaANew);
  const cTransfer = commit(amount, rTransfer);
  const vTilde = encryptAmount(amount, sX, sigmaANew);

  // New allowance (O10–O12).
  const rANew = deriveAllowR(dvk, sigmaANew);
  const cANew = commit(vANew, rANew);
  const aTildeNew = encryptAllowance(vANew, dvk, sigmaANew);

  // Recipient-auditor channel (O_a1–O_a4), two-wide.
  const sArX = ecdh(rE, kAudR);
  const mR = spongeSqueeze2(DOMAIN.AUDITOR_RECIPIENT, sArX, sigmaANew);
  const vAudR = frAdd(amount, mR[0]);
  const rAudR = frAdd(rTransfer, mR[1]);

  // Owner-auditor channel (O_a5–O_a9): amount, post-transfer allowance, and
  // the escrow of the new allowance blinding r_a'.
  const sAsX = ecdh(rE, kAudS);
  const { vAudS, bAudS: aAudS, rAudS } = encryptAuditorSender(sAsX, sigmaANew, {
    amount,
    vNew: vANew,
    rNew: rANew,
  });

  const inputs: NoirInputs = {
    sk_op: fieldIn(keys.sk),
    dvk_i: fieldIn(dvk),
    v_a: fieldIn(vA),
    r_a: fieldIn(rA),
    v_transfer: fieldIn(amount),
    r_e: fieldIn(rE),
    ...pointIn("c_a", cA),
    sigma_a: fieldIn(sigmaA),
    ...pointIn("y_op", keys.Y),
    ...pointIn("pvk_recipient", pvkRecipient),
    ...pointIn("k_aud_r", kAudR),
    ...pointIn("k_aud_s", kAudS),
    ...pointIn("c_a_new", cANew),
    ...pointIn("c_transfer", cTransfer),
    ...pointIn("r_e", rePoint),
    v_tilde: fieldIn(vTilde),
    a_tilde_new: fieldIn(aTildeNew),
    sigma_a_new: fieldIn(sigmaANew),
    v_tilde_aud_r: fieldIn(vAudR),
    r_tilde_aud_r: fieldIn(rAudR),
    v_tilde_aud_s: fieldIn(vAudS),
    a_tilde_aud_s: fieldIn(aAudS),
    r_tilde_aud_s: fieldIn(rAudS),
  };

  return {
    inputs,
    payload: {
      cANew,
      cTransfer,
      rE: rePoint,
      vTilde,
      aTildeNew,
      sigmaANew,
      vAudR,
      rAudR,
      vAudS,
      aAudS,
      rAudS,
    },
    next: { v: vANew, r: rANew, cA: cANew, sigmaA: sigmaANew, aTilde: aTildeNew },
    recipientView: { vTransfer: amount, rTransfer, cTransfer },
    rEScalar: rE,
  };
}
