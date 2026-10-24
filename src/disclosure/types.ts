/**
 * Wire types for the off-chain selective-disclosure protocol. Everything
 * here is JSON: field elements are
 * 0x-prefixed 32-byte hex, points are `{ x, y }` hex pairs. These objects are
 * what the two parties copy/paste (or POST) between each other — they never
 * touch the chain.
 */

import type {
  ConfidentialEvent,
  EventRef,
  SpenderTransferEvent,
  TransferEvent,
} from "../chain/events.js";

/**
 * The event families D-recipient and D-sender cover. One circuit serves both:
 * only the event nonce `σ_E` and the originating account differ
 * (selective-disclosure/README.md).
 */
export type DisclosableEvent = TransferEvent | SpenderTransferEvent;

/** Whether a decoded event is one a disclosure circuit covers. */
export function isDisclosableEvent(ev: ConfidentialEvent): ev is DisclosableEvent {
  return ev.type === "transfer" || ev.type === "spender_transfer";
}

/** `σ_E`: `σ` for a Transfer, `σ_a'` for a SpenderTransfer. */
export function disclosureNonce(ev: DisclosableEvent): bigint {
  return ev.type === "transfer" ? ev.sigma : ev.sigmaANew;
}

/**
 * The account whose ephemeral scalar keyed the event, i.e. who can D-sender
 * it, and the event field it is read from: `from` for a Transfer, the
 * `spender` (NOT the owner) for a SpenderTransfer
 * (d-sender.md#coverage-asymmetry-owner-cannot-d-sender-a-spendertransfer).
 */
export function disclosureOriginator(ev: DisclosableEvent): { field: "from" | "spender"; account: string } {
  return ev.type === "transfer"
    ? { field: "from", account: ev.from }
    : { field: "spender", account: ev.spender };
}

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
