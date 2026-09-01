/**
 * Wire types for the off-chain selective-disclosure protocol. Everything
 * here is JSON: field elements are
 * 0x-prefixed 32-byte hex, points are `{ x, y }` hex pairs. These objects are
 * what the two parties copy/paste (or POST) between each other — they never
 * touch the chain.
 */

import type { EventRef } from "../chain/events.js";

/** D-recipient: "this on-chain payment paid me this amount". */
export const DISCLOSE_RECIPIENT_CIRCUIT_ID = "disclose_recipient";
/** D-sender: "this on-chain payment was sent by me for this amount". */
export const DISCLOSE_SENDER_CIRCUIT_ID = "disclose_sender";

export type DisclosureCircuitId =
  | typeof DISCLOSE_RECIPIENT_CIRCUIT_ID
  | typeof DISCLOSE_SENDER_CIRCUIT_ID;

export const DISCLOSURE_CIRCUIT_IDS: readonly DisclosureCircuitId[] = [
  DISCLOSE_RECIPIENT_CIRCUIT_ID,
  DISCLOSE_SENDER_CIRCUIT_ID,
];

export interface JsonPoint {
  x: string;
  y: string;
}

/**
 * What the disclosure recipient sends to the holder: their
 * long-lived Grumpkin pubkey and a fresh per-request nonce. `(pR, nu)` binds
 * the resulting proof to this recipient and this request. The request is
 * circuit-agnostic — which claim the prover can make (received vs. sent) is
 * dictated by their relation to the event; the bundle's `circuitId` declares
 * it and pins the VK the verifier loads.
 */
export interface DisclosureRequest {
  pR: JsonPoint;
  nu: string;
}

/**
 * What the holder returns: the proof, the event reference, and the
 * recipient-bound disclosure ciphertext. Deliberately NOT included: the event
 * payload, the disclosing account, or any other public input — the verifier
 * reconstructs those from chain state (the trust-boundary rule).
 */
export interface DisclosureBundle {
  circuitId: DisclosureCircuitId;
  refE: EventRef;
  /** UltraHonk proof bytes, hex. */
  proof: string;
  /** Disclosure ciphertext: ephemeral key + sealed value. */
  rDisc: JsonPoint;
  vTildeDisc: string;
}

/** Recipient-side secret material, persisted by the verifying party only. */
export interface RecipientKeys {
  /** Secret scalar `r_R`. Never leaves the recipient. */
  rR: bigint;
  /** Published pubkey `P_R = r_R · H` as hex (what goes into requests). */
  pR: JsonPoint;
}
