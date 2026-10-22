/**
 * Withdraw-circuit witness. Debits `amount` from the spendable
 * balance to the public SEP-41 side, re-blinds the remainder, and emits a
 * sender-auditor balance checkpoint plus an escrow of the new blinding.
 *
 * Public-input order (16 fields, matches `storage.rs::withdraw`):
 *   C_spend, Y, addr_f, K_aud_s, a, C_spend', sigma, b_tilde, R_e,
 *   b_tilde_aud_s, r_tilde_aud_s
 */

import type { KeyPair } from "../crypto/keys.js";
import { H, commit, scalarMul, ecdh, type Point } from "../crypto/grumpkin.js";
import { randomScalar } from "../crypto/field.js";
import {
  deriveEphemeralRE,
  deriveSpendR,
  encryptAuditorSender,
  encryptBalance,
} from "../crypto/poseidon2.js";
import { fieldIn, pointIn, type NoirInputs } from "./common.js";

export interface WithdrawParams {
  /** Spender's contract-bound key set. */
  keys: KeyPair;
  /**
   * Current spendable-balance plaintext value `v`. Take `v`/`r` from
   * `StateEngine.spendableForProof()`, which checks them against on-chain
   * C_spend; this builder does not.
   */
  v: bigint;
  /** Current spendable-balance blinding factor `r` (opening of C_spend). */
  r: bigint;
  /** Public withdrawal amount `a` (0 ≤ a ≤ v). */
  amount: bigint;
  /** Sender's auditor key `K_aud_s` (from the auditor registry). */
  kAudS: Point;
  /** Optional fixed salt (defaults to a fresh random scalar). */
  sigma?: bigint;
  /**
   * Optional fixed ephemeral scalar `r_e ≠ 0`. Defaults to the derivation
   * `Poseidon2(EPHEMERAL_KEY, vk, sigma)` the spec requires of every holder
   * operation (docs/protocol/keys-and-commitments.md#ecdh-derived-blinding).
   */
  rE?: bigint;
}

export interface WithdrawWitness {
  inputs: NoirInputs;
  /** On-chain `WithdrawPayload`. `rE` is the POINT `R_e = r_e·H`. */
  payload: {
    cSpendNew: Point;
    bTilde: bigint;
    rE: Point;
    sigma: bigint;
    bAudS: bigint;
    rAudS: bigint;
  };
  /** Post-op spendable opening, for the local state engine. */
  next: { v: bigint; r: bigint; cSpend: Point };
}

export function buildWithdrawWitness(p: WithdrawParams): WithdrawWitness {
  const { keys, v, r, amount, kAudS } = p;
  if (amount < 0n) throw new Error("withdraw amount must be non-negative");
  const vNew = v - amount;
  if (vNew < 0n) throw new Error("withdraw amount exceeds spendable balance");

  const sigma = p.sigma ?? randomScalar();
  // Deterministic (vk + sigma), like transfer: the holder can re-derive r_e
  // from the emitted event alone. deriveEphemeralRE throws on the
  // negligible zero output (W8 requires r_e ≠ 0) — resample sigma then.
  const rE = p.rE ?? deriveEphemeralRE(keys.vk, sigma);

  const cSpend = commit(v, r);
  const rNew = deriveSpendR(keys.vk, sigma);
  const cSpendNew = commit(vNew, rNew);
  const bTilde = encryptBalance(vNew, keys.vk, sigma);
  const rePoint = scalarMul(rE, H);

  // Sender-auditor channel (W_a3): only the balance checkpoint (W_a4) and the
  // escrow of the new blinding r' (W_a5) — the withdrawn amount is public, so
  // the amount lane is not emitted.
  const sAsX = ecdh(rE, kAudS);
  const { bAudS, rAudS } = encryptAuditorSender(sAsX, sigma, { amount, vNew, rNew });

  const inputs: NoirInputs = {
    sk: fieldIn(keys.sk),
    v: fieldIn(v),
    r: fieldIn(r),
    r_e: fieldIn(rE),
    ...pointIn("c_spend", cSpend),
    ...pointIn("y", keys.Y),
    addr_f: fieldIn(keys.addrF),
    ...pointIn("k_aud_s", kAudS),
    a: fieldIn(amount),
    ...pointIn("c_spend_new", cSpendNew),
    sigma: fieldIn(sigma),
    b_tilde: fieldIn(bTilde),
    ...pointIn("r_e", rePoint),
    b_tilde_aud_s: fieldIn(bAudS),
    r_tilde_aud_s: fieldIn(rAudS),
  };

  return {
    inputs,
    payload: { cSpendNew, bTilde, rE: rePoint, sigma, bAudS, rAudS },
    next: { v: vNew, r: rNew, cSpend: cSpendNew },
  };
}
