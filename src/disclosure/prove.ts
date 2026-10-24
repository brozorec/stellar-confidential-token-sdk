/**
 * Holder-side disclosure proving:
 * take a recipient's request `(P_R, nu)` and a `Transfer` or `SpenderTransfer`
 * event, produce the proof bundle to hand back. One entry point per role:
 *
 *   - proveRecipientDisclosure — the event paid me (D-recipient)
 *   - proveSenderDisclosure    — I sent the event (D-sender; r_e is
 *                                re-derived from vk + the event's σ_E, and
 *                                an event it does not reproduce is reported
 *                                as not disclosable)
 *
 * The event nonce `σ_E` is `σ` for a Transfer and `σ_a'` for a
 * SpenderTransfer. The D-sender originator of a SpenderTransfer is the
 * spender; the owner cannot D-sender it.
 *
 * Pure orchestration over the witness builders + prover; the heavy lifting
 * (ECDH decrypt, U-block) is in witness/disclose-{recipient,sender}.ts.
 */

import type { KeyPair } from "../crypto/keys.js";
import type { Point } from "../crypto/grumpkin.js";
import { fromHex, toHex32, bytesToHex } from "../crypto/field.js";
import { eventRef, type ConfidentialEvent } from "../chain/events.js";
import type { CircuitProver } from "../proving/prover.js";
import { buildDiscloseRecipientWitness } from "../witness/disclose-recipient.js";
import {
  buildDiscloseSenderWitness,
  NotDisclosableError,
  type DiscloseSenderWitness,
} from "../witness/disclose-sender.js";
import {
  DISCLOSE_RECIPIENT_CIRCUIT_ID,
  DISCLOSE_SENDER_CIRCUIT_ID,
  disclosureNonce,
  isDisclosableEvent,
  type DisclosableEvent,
  type DisclosureBundle,
  type DisclosureCircuitId,
  type DisclosureRequest,
} from "./types.js";
import { pointFromJson, pointToJson } from "./recipient.js";

/**
 * Outcome of a D-sender attempt. `disclosable: false` carries neither a proof
 * nor an amount: the event's `R_e` is not `deriveEphemeralRE(vk, sigma) · H`
 * for these keys, so no D-sender proof exists for it (see
 * `senderEphemeralScalar`). It is not an error — the transfer may predate
 * deterministic ephemeral scalars.
 */
export type SenderDisclosureOutcome =
  | { disclosable: true; bundle: DisclosureBundle }
  | { disclosable: false; reason: NotDisclosableError["reason"] };

export async function proveRecipientDisclosure(params: {
  /** Holder's key set — must be the event's `to` account. */
  keys: KeyPair;
  /** The inbound transfer or spender-transfer event being disclosed. */
  event: DisclosableEvent;
  /** The recipient's request, received out-of-band. */
  request: DisclosureRequest;
  /** ZK prover over the shared disclose_recipient artifact (`circuits/disclosure/`). */
  prover: CircuitProver;
}): Promise<DisclosureBundle> {
  const { keys, event, request, prover } = params;
  requireZk(prover, DISCLOSE_RECIPIENT_CIRCUIT_ID);
  requireDisclosable(event, DISCLOSE_RECIPIENT_CIRCUIT_ID);
  const w = buildDiscloseRecipientWitness({
    keys,
    event: { rE: event.rE, sigma: disclosureNonce(event), vTilde: event.vTilde },
    pR: pointFromJson(request.pR),
    nu: fromHex(request.nu),
  });
  const { proof } = await prover.prove(w.inputs);
  return bundle(DISCLOSE_RECIPIENT_CIRCUIT_ID, event, proof, w);
}

export async function proveSenderDisclosure(params: {
  /**
   * Originator's key set: the event's `from` account for a Transfer, its
   * `spender` for a SpenderTransfer.
   */
  keys: KeyPair;
  /** The outbound transfer or spender-transfer event being disclosed. */
  event: DisclosableEvent;
  /** Transfer recipient's stored viewing key (read from the account at `E.to`). */
  pvkB: Point;
  /** The recipient's request, received out-of-band. */
  request: DisclosureRequest;
  /** ZK prover over the shared disclose_sender artifact (`circuits/disclosure/`). */
  prover: CircuitProver;
}): Promise<SenderDisclosureOutcome> {
  const { keys, event, pvkB, request, prover } = params;
  requireZk(prover, DISCLOSE_SENDER_CIRCUIT_ID);
  requireDisclosable(event, DISCLOSE_SENDER_CIRCUIT_ID);
  // The builder establishes disclosability first, so a non-disclosable event
  // never reaches the prover.
  let w: DiscloseSenderWitness;
  try {
    w = buildDiscloseSenderWitness({
      keys,
      event: { rE: event.rE, sigma: disclosureNonce(event), vTilde: event.vTilde },
      pvkB,
      pR: pointFromJson(request.pR),
      nu: fromHex(request.nu),
    });
  } catch (e) {
    if (e instanceof NotDisclosableError) return { disclosable: false, reason: e.reason };
    throw e;
  }
  const { proof } = await prover.prove(w.inputs);
  return { disclosable: true, bundle: bundle(DISCLOSE_SENDER_CIRCUIT_ID, event, proof, w) };
}

/** Disclosure proofs are ZK-flavour; a non-ZK proof never verifies against the pin. */
function requireZk(prover: CircuitProver, circuitId: DisclosureCircuitId): void {
  if (!prover.zk) {
    throw new Error(
      `${circuitId}: disclosure provers must be constructed with { zk: true } (circuits/disclosure/${circuitId}.vk.json)`,
    );
  }
}

/**
 * The type already says so; this catches an untyped caller passing another
 * event, which would otherwise fail deep in the witness builder.
 */
function requireDisclosable(event: ConfidentialEvent, circuitId: DisclosureCircuitId): void {
  if (!isDisclosableEvent(event)) {
    throw new Error(`${circuitId}: disclosures cover Transfer and SpenderTransfer events, not "${event.type}"`);
  }
}

function bundle(
  circuitId: DisclosureCircuitId,
  event: DisclosableEvent,
  proof: Uint8Array,
  w: { rDisc: Point; vTildeDisc: bigint },
): DisclosureBundle {
  return {
    circuitId,
    refE: eventRef(event),
    proof: "0x" + bytesToHex(proof),
    rDisc: pointToJson(w.rDisc),
    vTildeDisc: toHex32(w.vTildeDisc),
  };
}
