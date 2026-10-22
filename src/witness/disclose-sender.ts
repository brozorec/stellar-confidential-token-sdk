/**
 * D-sender disclosure-circuit witness.
 *
 * The ORIGINATOR of a confidential transfer proves to a third party that they
 * paid exactly `v_tx` to the on-chain `to` recorded in the event. The event
 * ciphertext is keyed to the recipient's `PVK_B`, so the sender's necessary
 * witness is the ephemeral scalar `r_e` from transfer time — recomputed as
 * `Poseidon2(EPHEMERAL_KEY, vk, sigma_E)` from the event's public `sigma`
 * (see `deriveEphemeralRE`), so no per-transfer state is needed.
 *
 * Public-input order (matches `circuits/disclosure/noir/disclose_sender/src/main.nr`):
 *   addr_f, PVK_A, R_e, sigma, v_tilde, PVK_B, P_R, nu, R_disc, v_tilde_disc
 */

import type { KeyPair } from "../crypto/keys.js";
import { H, scalarMul, ecdh, type Point } from "../crypto/grumpkin.js";
import { randomScalar } from "../crypto/field.js";
import { DOMAIN } from "../crypto/constants.js";
import {
  decryptWithDomain,
  deriveEphemeralRE,
  encryptDisclosure,
  ZeroEphemeralScalarError,
} from "../crypto/poseidon2.js";
import { fieldIn, pointIn, type NoirInputs } from "./common.js";

/** The per-event fields of the on-chain `Transfer` being disclosed. */
export interface DisclosedTransferFields {
  rE: Point;
  sigma: bigint;
  vTilde: bigint;
}

export interface DiscloseSenderParams {
  /** Originator's contract-bound key set (the event's `from` account). */
  keys: KeyPair;
  event: DisclosedTransferFields;
  /** Transfer recipient's stored viewing key (from the account at `E.to`). */
  pvkB: Point;
  /** Disclosure recipient's Grumpkin pubkey `P_R`. */
  pR: Point;
  /** Recipient-supplied request nonce `nu`. */
  nu: bigint;
  rDisc?: bigint;
}

export interface DiscloseSenderWitness {
  inputs: NoirInputs;
  /** Plaintext amount the event decrypts to (what the proof discloses). */
  vTx: bigint;
  /** Disclosure ciphertext — travels in the bundle alongside the proof. */
  rDisc: Point;
  vTildeDisc: bigint;
}

/**
 * The transfer is not disclosable by these keys: `deriveEphemeralRE(vk,
 * sigma_E) · H` is not the event's `R_e`. Either the keys are not the event's
 * originator, or the transfer was sent with a non-derived ephemeral scalar
 * (one predating deterministic `r_e`, or an explicit `rE` override). This is
 * an outcome, not a proving failure (stellar-confidential
 * docs/sdk/clients.md#disclosure-construction); {@link proveSenderDisclosure}
 * returns it as a value instead of throwing.
 */
export class NotDisclosableError extends Error {
  readonly reason = "ephemeral-scalar-mismatch" as const;
  constructor() {
    super(
      "transfer is not disclosable by these keys: Poseidon2(EPHEMERAL_KEY, vk, sigma) · H does not reproduce the event's R_e",
    );
    this.name = "NotDisclosableError";
  }
}

/**
 * Establish D-sender disclosability (docs/sdk/clients.md#disclosure-construction):
 * derive the candidate `r_e` from `(vk, sigma_E)` and compare `r_e · H` with
 * the event's `R_e`. Returns the scalar, or `null` when the event is not
 * disclosable by `keys`. Authoritative, and costs one Poseidon2 call and one
 * scalar multiplication — check this rather than a stored per-transfer flag.
 */
export function senderEphemeralScalar(
  keys: KeyPair,
  event: Pick<DisclosedTransferFields, "rE" | "sigma">,
): bigint | null {
  let rE: bigint;
  try {
    rE = deriveEphemeralRE(keys.vk, event.sigma);
  } catch (e) {
    // A zero derivation (~2^-254) can never match a valid R_e. Anything else
    // (a malformed key or sigma) is a caller bug, not an outcome.
    if (e instanceof ZeroEphemeralScalarError) return null;
    throw e;
  }
  return scalarMul(rE, H).equals(event.rE) ? rE : null;
}

/** @throws {NotDisclosableError} when {@link senderEphemeralScalar} returns null. */
export function buildDiscloseSenderWitness(p: DiscloseSenderParams): DiscloseSenderWitness {
  const { keys, event, pvkB, pR, nu } = p;

  // DS3 — only a re-derivable r_e can be disclosed.
  const rEScalar = senderEphemeralScalar(keys, event);
  if (rEScalar === null) throw new NotDisclosableError();

  // DS4/DS5 — reconstruct the recipient-side decryption from the sender side.
  const sB = ecdh(rEScalar, pvkB);
  const vTx = decryptWithDomain(event.vTilde, DOMAIN.TRANSFER_AMOUNT, sB, event.sigma);
  if (vTx >= 1n << 127n) {
    throw new Error(
      "event does not decrypt to a valid amount — does PVK_B belong to the event's recipient?",
    );
  }

  // U-block — seal v_tx to the disclosure recipient.
  const rDiscScalar = p.rDisc ?? randomScalar();
  const rDisc = scalarMul(rDiscScalar, H);
  const sDisc = ecdh(rDiscScalar, pR);
  const vTildeDisc = encryptDisclosure(vTx, sDisc, nu);

  const inputs: NoirInputs = {
    sk: fieldIn(keys.sk),
    r_e: fieldIn(rEScalar),
    v_tx: fieldIn(vTx),
    r_disc: fieldIn(rDiscScalar),
    addr_f: fieldIn(keys.addrF),
    ...pointIn("pvk_a", keys.PVK),
    ...pointIn("r_e", event.rE),
    sigma: fieldIn(event.sigma),
    v_tilde: fieldIn(event.vTilde),
    ...pointIn("pvk_b", pvkB),
    ...pointIn("p_r", pR),
    nu: fieldIn(nu),
    ...pointIn("r_disc", rDisc),
    v_tilde_disc: fieldIn(vTildeDisc),
  };

  return { inputs, vTx, rDisc, vTildeDisc };
}
