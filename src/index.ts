/**
 * stellar-confidential-token-sdk — client SDK for confidential tokens on Stellar.
 *
 * Layers:
 *   - crypto/   Grumpkin + Poseidon2 + key/address derivation (parity-checked
 *               against the circuits)
 *   - witness/  per-circuit witness builders (register, withdraw, transfer)
 *   - proving/  UltraHonk proving via bb.js (keccak transcript)
 *   - chain/    RPC client, XDR payload envelopes, op submitters, event ingest
 *   - state/    RPC-only balance reconstruction with local persistence
 *   - disclosure/  off-chain selective disclosure (prove + verify)
 *   - auditor/  auditor-side event decryption
 */

export * from "./crypto/index.js";
export * from "./witness/index.js";
export * from "./proving/index.js";
export * from "./chain/index.js";
export * from "./state/index.js";
export * from "./disclosure/index.js";
export * from "./auditor/index.js";
