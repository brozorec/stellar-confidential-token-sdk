// Off-chain selective-disclosure layer.
// Holder side: proveDisclosure. Receiver side: generateRecipientKeys,
// newDisclosureRequest, verifyDisclosure. Both sides load the SAME circuit
// artifact + VK from `circuits/disclosure/` (the shared-artifact rule).
export * from "./types.js";
export * from "./recipient.js";
export * from "./prove.js";
export * from "./verify.js";
