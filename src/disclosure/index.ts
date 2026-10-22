// Off-chain selective-disclosure layer.
// Holder side: proveRecipientDisclosure, proveSenderDisclosure. Receiver side:
// generateRecipientKeys, newDisclosureRequest, verifyDisclosure. Both sides
// load the SAME circuit artifact + VK from `circuits/disclosure/` (the
// shared-artifact rule) into a `{ zk: true }` CircuitProver.
export * from "./types.js";
export * from "./recipient.js";
export * from "./prove.js";
export * from "./verify.js";
