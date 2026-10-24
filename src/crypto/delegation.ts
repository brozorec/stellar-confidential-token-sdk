/**
 * Delegation-key and allowance openings (docs/protocol/operations/set-spender.md).
 *
 * A `set_spender` writes a `SpenderDelegation` entry whose allowance
 * commitment `C_a = Com(v_a, r_a)` is keyed by the delegation viewing key
 * `dvk = Poseidon2(DELEGATION_VIEWING_KEY, vk_owner, op_i)`:
 *
 *   r_a     = Poseidon2(ALLOWANCE_RANDOMNESS, dvk, σ_a)
 *   a_tilde = v_a + Poseidon2(ENCRYPTED_ALLOWANCE, dvk, σ_a)
 *
 * The owner derives `dvk` from `vk`. The spender recovers it from the entry's
 * `escrowed_dvk = (R_x, dvk_cipher)`, an ECDH escrow under its spending key
 * `Y_op`: `dvk = dvk_cipher − Poseidon2(ESCROWED_DELEGATION_VIEWING_KEY, s, op_i)`
 * with `s = ecdh(sk_op, R)`. Only `R.x` is stored, and `ecdh` absorbs `S.y`,
 * so `R` and `−R` give different masks: {@link recoverEscrowedDvk} tries both
 * and keeps the one whose allowance opening re-commits to `C_a`.
 *
 * Both sides accept an opening only through {@link openAllowanceEntry}, so
 * every opening they return is checked against the entry's `C_a`.
 */

import { DOMAIN } from "./constants.js";
import { commit, ecdh, pointsWithX, type Point } from "./grumpkin.js";
import { decryptWithDomain, deriveAllowR } from "./poseidon2.js";

/** Opening `(v_a, r_a)` of an allowance commitment `C_a`. */
export interface AllowanceOpening {
  v: bigint;
  r: bigint;
}

/** The on-chain `escrowed_dvk: BytesN<64>`, split into its two field limbs. */
export interface EscrowedDvk {
  /** `R.x` of the escrow ephemeral (the `set_spender` proof's `R_e.x`). */
  rX: bigint;
  /** `dvk + Poseidon2(ESCROWED_DELEGATION_VIEWING_KEY, s, op_i)`. */
  cipher: bigint;
}

/** The allowance fields of an on-chain `SpenderDelegation` entry. */
export interface AllowanceEntry {
  aTilde: bigint;
  allowanceSalt: bigint;
  allowanceCommitment: Point;
}

/** Open an allowance from its `(a_tilde, σ_a)` under `dvk`. */
export function openAllowanceUnder(dvk: bigint, aTilde: bigint, sigmaA: bigint): AllowanceOpening {
  return {
    v: decryptWithDomain(aTilde, DOMAIN.ENCRYPTED_ALLOWANCE, dvk, sigmaA),
    r: deriveAllowR(dvk, sigmaA),
  };
}

/**
 * Open a delegation entry's allowance under `dvk`, or `null` if the opening
 * does not re-commit to the entry's `C_a`: `dvk` is not this delegation's key.
 */
export function openAllowanceEntry(dvk: bigint, entry: AllowanceEntry): AllowanceOpening | null {
  const opening = openAllowanceUnder(dvk, entry.aTilde, entry.allowanceSalt);
  return commit(opening.v, opening.r).equals(entry.allowanceCommitment) ? opening : null;
}

/**
 * Recover `dvk` from an escrow addressed to the spender holding `skOp`, and
 * the allowance opening it yields. A candidate is accepted only if its opening
 * re-commits to `cA`, so a returned result is verified against the entry; a
 * wrong-candidate false accept needs a Poseidon2 collision. Returns `null`
 * when neither candidate does: `skOp` is not the delegation's spender, `opI`
 * is not its address, or `R_x` is not on the curve.
 */
export function recoverEscrowedDvk(
  skOp: bigint,
  opI: bigint,
  entry: AllowanceEntry & { escrowedDvk: EscrowedDvk },
): { dvk: bigint; opening: AllowanceOpening } | null {
  const candidates = pointsWithX(entry.escrowedDvk.rX);
  if (!candidates) return null;
  for (const R of candidates) {
    const s = ecdh(skOp, R);
    const dvk = decryptWithDomain(entry.escrowedDvk.cipher, DOMAIN.ESCROWED_DELEGATION_VIEWING_KEY, s, opI);
    const opening = openAllowanceEntry(dvk, entry);
    if (opening) return { dvk, opening };
  }
  return null;
}
