/**
 * Holder-side disclosure proving:
 * take a recipient's request `(P_R, nu)` and a `Transfer` event, produce the
 * proof bundle to hand back. One entry point per role:
 *
 *   - proveRecipientDisclosure — the event paid me (D-recipient)
 *   - proveSenderDisclosure    — I sent the event (D-sender; r_e is
 *                                re-derived from vk + the event's sigma)
 *
 * Pure orchestration over the witness builders + prover; the heavy lifting
 * (ECDH decrypt, U-block) is in witness/disclose-{recipient,sender}.ts.
 */

import type { KeyPair } from "../crypto/keys.js";
import type { Point } from "../crypto/grumpkin.js";
import { fromHex, toHex32, bytesToHex } from "../crypto/field.js";
import type { TransferEvent } from "../chain/events.js";
import { eventRef } from "../chain/events.js";
import type { CircuitProver } from "../proving/prover.js";
import { buildDiscloseRecipientWitness } from "../witness/disclose-recipient.js";
import { buildDiscloseSenderWitness } from "../witness/disclose-sender.js";
import {
  DISCLOSE_RECIPIENT_CIRCUIT_ID,
  DISCLOSE_SENDER_CIRCUIT_ID,
  type DisclosureBundle,
  type DisclosureCircuitId,
  type DisclosureRequest,
} from "./types.js";
import { pointFromJson, pointToJson } from "./recipient.js";

export async function proveRecipientDisclosure(params: {
  /** Holder's key set — must be the event's `to` account. */
  keys: KeyPair;
  /** The inbound transfer event being disclosed. */
  event: TransferEvent;
  /** The recipient's request, received out-of-band. */
  request: DisclosureRequest;
  /** Prover over the shared disclose_recipient artifact (`circuits/disclosure/`). */
  prover: CircuitProver;
}): Promise<DisclosureBundle> {
  const { keys, event, request, prover } = params;
  const w = buildDiscloseRecipientWitness({
    keys,
    event: { rE: event.rE, sigma: event.sigma, vTilde: event.vTilde },
    pR: pointFromJson(request.pR),
    nu: fromHex(request.nu),
  });
  const { proof } = await prover.prove(w.inputs);
  return bundle(DISCLOSE_RECIPIENT_CIRCUIT_ID, event, proof, w);
}

export async function proveSenderDisclosure(params: {
  /** Originator's key set — must be the event's `from` account. */
  keys: KeyPair;
  /** The transfer's ephemeral scalar, re-derived via `deriveEphemeralRE`. */
  rEScalar: bigint;
  /** The outbound transfer event being disclosed. */
  event: TransferEvent;
  /** Transfer recipient's stored viewing key (read from the account at `E.to`). */
  pvkB: Point;
  /** The recipient's request, received out-of-band. */
  request: DisclosureRequest;
  /** Prover over the shared disclose_sender artifact (`circuits/disclosure/`). */
  prover: CircuitProver;
}): Promise<DisclosureBundle> {
  const { keys, rEScalar, event, pvkB, request, prover } = params;
  const w = buildDiscloseSenderWitness({
    keys,
    rEScalar,
    event: { rE: event.rE, sigma: event.sigma, vTilde: event.vTilde },
    pvkB,
    pR: pointFromJson(request.pR),
    nu: fromHex(request.nu),
  });
  const { proof } = await prover.prove(w.inputs);
  return bundle(DISCLOSE_SENDER_CIRCUIT_ID, event, proof, w);
}

function bundle(
  circuitId: DisclosureCircuitId,
  event: TransferEvent,
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
