/**
 * SetSpender-circuit witness. The owner moves `amount` (`v_a`) out of its
 * spendable balance into a per-spender allowance `C_a`, escrows the
 * delegation viewing key `dvk` to the spender under `Y_op`, and emits the
 * owner-auditor channel plus the auditor-side escrow of `r_a` (S14).
 *
 * Public-input order (26 fields, matches `storage.rs::set_spender`):
 *   C_spend, Y, Y_op, op_i, addr_f, K_aud_s, C_spend', C_a,
 *   escrowed_dvk (R_x, dvk_cipher), b_tilde, a_tilde, sigma, sigma_a, R_e,
 *   v_tilde_aud_s, b_tilde_aud_s, r_tilde_aud_s, r_a_tilde_aud_s
 */

import type { KeyPair } from "../crypto/keys.js";
import { H, commit, scalarMul, ecdh, pointCoords, type Point } from "../crypto/grumpkin.js";
import { randomScalar } from "../crypto/field.js";
import { addressToField } from "../crypto/address.js";
import type { EscrowedDvk } from "../crypto/delegation.js";
import {
  deriveAllowR,
  deriveEphemeralRE,
  deriveSpendR,
  dvkFromVkOp,
  encryptAllowance,
  encryptAuditorSender,
  encryptBalance,
  encryptEscAllowRAuditor,
  encryptEscDvk,
} from "../crypto/poseidon2.js";
import { fieldIn, pointIn, type NoirInputs } from "./common.js";

export interface SetSpenderParams {
  /** Owner's contract-bound key set. */
  keys: KeyPair;
  /**
   * Owner's current spendable plaintext / blinding. Take them from
   * `StateEngine.spendableForProof()`, which checks them against on-chain
   * C_spend; this builder does not.
   */
  v: bigint;
  r: bigint;
  /** Allowance escrowed to the spender, `v_a` (0 ≤ v_a ≤ v). */
  amount: bigint;
  /** Spender's Stellar address (the `spender` argument; `op_i` is its address-as-field). */
  spender: string;
  /** Spender's spending key `Y_op` (its registered `spending_public_key`). */
  yOp: Point;
  /** Owner's auditor key `K_aud_s`. */
  kAudS: Point;
  /** Owner-channel salt (defaults to a fresh random scalar). */
  sigma?: bigint;
  /** Allowance salt `σ_a` (defaults to a fresh random scalar). */
  sigmaA?: bigint;
  /**
   * Optional fixed ephemeral scalar `r_e ≠ 0`. Defaults to
   * `Poseidon2(EPHEMERAL_KEY, vk, sigma)` from the owner's `vk`
   * (docs/protocol/keys-and-commitments.md#ecdh-derived-blinding).
   */
  rE?: bigint;
}

export interface SetSpenderWitness {
  inputs: NoirInputs;
  /** On-chain `SetSpenderPayload`. `rE` is the POINT `R_e = r_e·H`. */
  payload: {
    cSpendNew: Point;
    cA: Point;
    escrowedDvk: EscrowedDvk;
    bTilde: bigint;
    aTilde: bigint;
    rE: Point;
    sigma: bigint;
    sigmaA: bigint;
    vAudS: bigint;
    bAudS: bigint;
    rAudS: bigint;
    raAudS: bigint;
  };
  /** Post-op owner spendable opening, for the local state engine. */
  next: { v: bigint; r: bigint; cSpend: Point };
  /** The delegation the contract stores: its key, salt and allowance opening. */
  allowance: { dvk: bigint; sigmaA: bigint; v: bigint; r: bigint; cA: Point; aTilde: bigint };
  /** The ephemeral SCALAR `r_e`, for inspection and tests. */
  rEScalar: bigint;
}

export function buildSetSpenderWitness(p: SetSpenderParams): SetSpenderWitness {
  const { keys, v, r, amount, yOp, kAudS } = p;
  if (amount < 0n) throw new Error("allowance must be non-negative");
  const vNew = v - amount;
  if (vNew < 0n) throw new Error("allowance exceeds spendable balance");

  const sigma = p.sigma ?? randomScalar();
  const sigmaA = p.sigmaA ?? randomScalar();
  // Deterministic (owner vk + sigma), like transfer and withdraw. The same
  // r_e keys the auditor channel and the dvk escrow (S12(a)).
  const rE = p.rE ?? deriveEphemeralRE(keys.vk, sigma);
  const opI = addressToField(p.spender);

  // Owner balance split (S3, S9–S11).
  const cSpend = commit(v, r);
  const rNew = deriveSpendR(keys.vk, sigma);
  const cSpendNew = commit(vNew, rNew);
  const bTilde = encryptBalance(vNew, keys.vk, sigma);
  const rePoint = scalarMul(rE, H);

  // Delegation + allowance (S5–S8).
  const dvk = dvkFromVkOp(keys.vk, opI);
  const rA = deriveAllowR(dvk, sigmaA);
  const cA = commit(amount, rA);
  const aTilde = encryptAllowance(amount, dvk, sigmaA);

  // dvk escrow to the spender (S12): R_x is R_e.x, the mask is keyed by
  // ecdh(r_e, Y_op).
  const escrowedDvk: EscrowedDvk = {
    rX: pointCoords(rePoint).x,
    cipher: encryptEscDvk(dvk, ecdh(rE, yOp), opI),
  };

  // Owner-auditor channel (S_a2–S_a6): escrowed amount, post-escrow balance,
  // new spendable blinding; then the r_a escrow over the same scalar (S14).
  const sAsX = ecdh(rE, kAudS);
  const { vAudS, bAudS, rAudS } = encryptAuditorSender(sAsX, sigma, { amount, vNew, rNew });
  const raAudS = encryptEscAllowRAuditor(rA, sAsX, opI);

  const inputs: NoirInputs = {
    sk: fieldIn(keys.sk),
    v: fieldIn(v),
    r: fieldIn(r),
    v_a: fieldIn(amount),
    r_e: fieldIn(rE),
    ...pointIn("c_spend", cSpend),
    ...pointIn("y", keys.Y),
    ...pointIn("y_op", yOp),
    op_i: fieldIn(opI),
    addr_f: fieldIn(keys.addrF),
    ...pointIn("k_aud_s", kAudS),
    ...pointIn("c_spend_new", cSpendNew),
    ...pointIn("c_a", cA),
    escrowed_dvk_r_x: fieldIn(escrowedDvk.rX),
    escrowed_dvk_cipher: fieldIn(escrowedDvk.cipher),
    b_tilde: fieldIn(bTilde),
    a_tilde: fieldIn(aTilde),
    sigma: fieldIn(sigma),
    sigma_a: fieldIn(sigmaA),
    ...pointIn("r_e", rePoint),
    v_tilde_aud_s: fieldIn(vAudS),
    b_tilde_aud_s: fieldIn(bAudS),
    r_tilde_aud_s: fieldIn(rAudS),
    r_a_tilde_aud_s: fieldIn(raAudS),
  };

  return {
    inputs,
    payload: {
      cSpendNew,
      cA,
      escrowedDvk,
      bTilde,
      aTilde,
      rE: rePoint,
      sigma,
      sigmaA,
      vAudS,
      bAudS,
      rAudS,
      raAudS,
    },
    next: { v: vNew, r: rNew, cSpend: cSpendNew },
    allowance: { dvk, sigmaA, v: amount, r: rA, cA, aTilde },
    rEScalar: rE,
  };
}
