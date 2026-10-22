/**
 * Poseidon2 over BN254 `F_r`, reconstructed on top of the raw permutation from
 * `@zkpassport/poseidon2` so the sponge matches `circuits/lib/src/lib.nr`
 * byte-for-byte. We deliberately do NOT use the package's own `poseidon2Hash`
 * sponge — its padding/IV convention is its own and we cannot let it drift from
 * the circuit's.
 *
 * Sponge (lib.nr `sponge`): width 4, rate 3, capacity 1.
 *   - `iv = len * 2^64` placed at `state[3]`; state starts `[0,0,0,iv]`.
 *   - absorb 3 elements at a time by ADDING into `state[0..3]`, then permute.
 *   - one trailing permute for any non-multiple-of-3 remainder.
 *   - squeeze `state[0]`.
 *
 * `poseidon_with_domain(d, inputs)` prepends the domain tag, so it is just
 * `sponge([d, ...inputs])`.
 */

import { permute } from "@zkpassport/poseidon2";

import { POSEIDON2_IV_BASE, DOMAIN } from "./constants.js";
import { frMod, frAdd } from "./field.js";

/** Generic sponge over `F_r`, matching `lib.nr::sponge`. */
export function sponge(inputs: bigint[]): bigint {
  const m = inputs.length;
  const iv = frMod(BigInt(m) * POSEIDON2_IV_BASE);
  let state: bigint[] = [0n, 0n, 0n, iv];

  const full = Math.floor(m / 3);
  for (let i = 0; i < full; i++) {
    state[0] = frAdd(state[0]!, inputs[i * 3]!);
    state[1] = frAdd(state[1]!, inputs[i * 3 + 1]!);
    state[2] = frAdd(state[2]!, inputs[i * 3 + 2]!);
    state = permute(state);
  }

  const remainder = m - full * 3;
  // `m === 0` also permutes: the on-chain sponge always permutes before
  // squeezing, so the empty input hashes to `permute([0,0,0,0])[0]` rather than
  // to 0. Unreachable through `poseidonWithDomain` (the tag guarantees m >= 1),
  // but kept in lockstep with `lib.nr::sponge`.
  if (remainder !== 0 || m === 0) {
    for (let i = 0; i < remainder; i++) {
      state[i] = frAdd(state[i]!, inputs[full * 3 + i]!);
    }
    state = permute(state);
  }

  return state[0]!;
}

/** The single Poseidon2 funnel: domain tag is always the first absorbed field. */
export function poseidonWithDomain(d: bigint, inputs: bigint[]): bigint {
  return sponge([d, ...inputs]);
}

/**
 * Three-squeeze sponge (`lib.nr::sponge_squeeze_3`): absorbs `(d, s, sigma)` —
 * `s` being the ECDH shared-secret scalar from {@link ecdh} — in one block and
 * returns `[state[0], state[1], state[2]]`. Lane 0 is the amount mask, lane 1
 * the balance/allowance mask, lane 2 the escrow of the blinding the operation
 * writes. Only the sender-auditor channel ({@link DOMAIN.AUDITOR_SENDER}) is
 * read three-wide.
 */
export function spongeSqueeze3(d: bigint, sx: bigint, sigma: bigint): [bigint, bigint, bigint] {
  const iv = frMod(3n * POSEIDON2_IV_BASE);
  const state = permute([d, sx, sigma, iv]);
  return [state[0]!, state[1]!, state[2]!];
}

/**
 * Two-squeeze sponge (`lib.nr::sponge_squeeze_2`): the first two lanes of
 * {@link spongeSqueeze3} — same absorb, same permutation. Index 0 is the amount
 * mask, index 1 the randomness mask. Only the recipient-auditor channel
 * ({@link DOMAIN.AUDITOR_RECIPIENT}) is read two-wide.
 */
export function spongeSqueeze2(d: bigint, sx: bigint, sigma: bigint): [bigint, bigint] {
  const [m0, m1] = spongeSqueeze3(d, sx, sigma);
  return [m0, m1];
}

// ---------------------------------------------------------------------------
// Key / randomness derivations (mirror lib.nr one-for-one)
// ---------------------------------------------------------------------------

/** `vk = Poseidon2(VIEWING_KEY, sk, addr_f)`. */
export const vkFromSk = (sk: bigint, addrF: bigint): bigint =>
  poseidonWithDomain(DOMAIN.VIEWING_KEY, [sk, addrF]);

/** `dvk = Poseidon2(DELEGATION_VIEWING_KEY, vk, op_i)`. */
export const dvkFromVkOp = (vk: bigint, opI: bigint): bigint =>
  poseidonWithDomain(DOMAIN.DELEGATION_VIEWING_KEY, [vk, opI]);

/** `r' = Poseidon2(SPEND_RANDOMNESS, vk, sigma)`. */
export const deriveSpendR = (vk: bigint, sigma: bigint): bigint =>
  poseidonWithDomain(DOMAIN.SPEND_RANDOMNESS, [vk, sigma]);

/** `r_a = Poseidon2(ALLOWANCE_RANDOMNESS, dvk, sigma_a)`. */
export const deriveAllowR = (dvk: bigint, sigmaA: bigint): bigint =>
  poseidonWithDomain(DOMAIN.ALLOWANCE_RANDOMNESS, [dvk, sigmaA]);

/**
 * `r_transfer = Poseidon2(TRANSFER_BLINDING, s, sigma)`. `s` is the recipient-ECDH
 * shared-secret SCALAR from {@link ecdh} (no longer a bare x-coordinate).
 */
export const deriveTransferBlind = (s: bigint, sigma: bigint): bigint =>
  poseidonWithDomain(DOMAIN.TRANSFER_BLINDING, [s, sigma]);

/**
 * Deterministic ephemeral scalar `r_e = Poseidon2(EPHEMERAL_KEY, vk, sigma)`.
 *
 * The circuits leave `r_e` a free witness, so deriving it (instead of
 * sampling) changes nothing on-chain — but it lets the SENDER re-derive the
 * scalar for any past outgoing transfer from `vk` plus the event's public
 * `sigma`, which is what makes D-sender disclosures work without retaining
 * per-transfer state. Uniqueness comes from `sigma` (fresh per attempt);
 * secrecy from `vk`. Throws {@link ZeroEphemeralScalarError} on the
 * ~2⁻²⁵⁴-probability zero output (T8/W8 require `r_e ≠ 0`) — resample `sigma`
 * if that ever happens.
 */
export const deriveEphemeralRE = (vk: bigint, sigma: bigint): bigint => {
  const rE = poseidonWithDomain(DOMAIN.EPHEMERAL_KEY, [vk, sigma]);
  if (rE === 0n) throw new ZeroEphemeralScalarError();
  return rE;
};

/** {@link deriveEphemeralRE} produced the forbidden `r_e = 0`. */
export class ZeroEphemeralScalarError extends Error {
  constructor() {
    super("derived r_e is zero — resample sigma");
    this.name = "ZeroEphemeralScalarError";
  }
}

// ---------------------------------------------------------------------------
// Encrypted scalars: ciphertext = plaintext + Poseidon2(tag, ...)
// ---------------------------------------------------------------------------

/** `v_tilde = v_transfer + Poseidon2(TRANSFER_AMOUNT, s, sigma)`. */
export const encryptAmount = (vTransfer: bigint, s: bigint, sigma: bigint): bigint =>
  frAdd(vTransfer, poseidonWithDomain(DOMAIN.TRANSFER_AMOUNT, [s, sigma]));

/** `b_tilde = v_new + Poseidon2(ENCRYPTED_BALANCE, vk, sigma)`. */
export const encryptBalance = (vNew: bigint, vk: bigint, sigma: bigint): bigint =>
  frAdd(vNew, poseidonWithDomain(DOMAIN.ENCRYPTED_BALANCE, [vk, sigma]));

/** `a_tilde = v_a + Poseidon2(ENCRYPTED_ALLOWANCE, dvk, sigma_a)`. */
export const encryptAllowance = (vA: bigint, dvk: bigint, sigmaA: bigint): bigint =>
  frAdd(vA, poseidonWithDomain(DOMAIN.ENCRYPTED_ALLOWANCE, [dvk, sigmaA]));

/** `escrowed_dvk = dvk + Poseidon2(ESCROWED_DELEGATION_VIEWING_KEY, s, op_i)`. */
export const encryptEscDvk = (dvk: bigint, s: bigint, opI: bigint): bigint =>
  frAdd(dvk, poseidonWithDomain(DOMAIN.ESCROWED_DELEGATION_VIEWING_KEY, [s, opI]));

/**
 * Sender-auditor channel ({@link DOMAIN.AUDITOR_SENDER}, read three-wide):
 * with `m = sponge_squeeze_3(AUDITOR_SENDER, s, sigma)`,
 * `v_tilde_aud_s = amount + m[0]`, the balance checkpoint
 * `b_tilde_aud_s = v_new + m[1]`, and the escrow of the new spendable blinding
 * `r_tilde_aud_s = r_new + m[2]`. Transfer emits all three (T_a6–T_a9);
 * withdraw only the checkpoint lanes (W_a3–W_a5) — its amount is public. Every
 * lane adds in-circuit, so mod r (`frAdd`), the blinding escrow included.
 */
export function encryptAuditorSender(
  sAs: bigint,
  sigma: bigint,
  plain: { amount: bigint; vNew: bigint; rNew: bigint },
): { vAudS: bigint; bAudS: bigint; rAudS: bigint } {
  const [m0, m1, m2] = spongeSqueeze3(DOMAIN.AUDITOR_SENDER, sAs, sigma);
  return {
    vAudS: frAdd(plain.amount, m0),
    bAudS: frAdd(plain.vNew, m1),
    rAudS: frAdd(plain.rNew, m2),
  };
}

/**
 * `r_a_tilde_aud_s = r_a + Poseidon2(ESCROWED_ALLOWANCE_BLINDING_AUDITOR, s_a_s, op_i)`
 * — the set_spender allowance-blinding escrow to the owner's auditor (S14).
 */
export const encryptEscAllowRAuditor = (rA: bigint, sAs: bigint, opI: bigint): bigint =>
  frAdd(rA, poseidonWithDomain(DOMAIN.ESCROWED_ALLOWANCE_BLINDING_AUDITOR, [sAs, opI]));

/**
 * `v_tilde_disc = v_tx + Poseidon2(DISCLOSURE, s_disc, nu)` — the U3 stage
 * of every selective-disclosure circuit, where `s_disc = ecdh(r_disc, P_R)`
 * is the ECDH scalar (U2), not a raw x-coordinate. The recipient inverts it
 * with {@link decryptWithDomain} after recovering `s_disc = ecdh(r_R, R_disc)`.
 */
export const encryptDisclosure = (vTx: bigint, sDisc: bigint, nu: bigint): bigint =>
  frAdd(vTx, poseidonWithDomain(DOMAIN.DISCLOSURE, [sDisc, nu]));

/**
 * Decrypt a scalar ciphertext: `plaintext = ciphertext - Poseidon2(tag, ...)`.
 * Used by the state engine to recover `v_new` from an emitted `b_tilde`, etc.
 */
export const decryptWithDomain = (
  ciphertext: bigint,
  d: bigint,
  a: bigint,
  b: bigint,
): bigint => frMod(ciphertext - poseidonWithDomain(d, [a, b]));
