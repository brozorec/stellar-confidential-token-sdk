/**
 * Human-readable messages for on-chain contract errors.
 *
 * Soroban surfaces a failed contract call as a `HostError` whose string carries
 * `Error(Contract, #NNNN)`, where `NNNN` is a `#[contracterror]` discriminant.
 * The raw HostError (with its diagnostic event log) is unreadable in a UI, so
 * this maps the known codes to plain language.
 *
 * Every `#[contracterror]` code in stellar-contracts is unique across the
 * workspace (Architecture.md "Error Codes"), so a code identifies its enum even
 * when the failing contract is deep in the call tree. Codes mirror these enums
 * at stellar-contracts v0.8.0; keep in sync if they change:
 *   - CryptoError            1400–1499  (stellar_contract_utils::crypto)
 *   - AccessControlError     2000–2099  (stellar_access::access_control)
 *   - OwnableError           2100–2199  (stellar_access::ownable)
 *   - RoleTransferError      2200–2299  (stellar_access::role_transfer)
 *   - AuditorError           3300–3399  (stellar_confidential::auditor)
 *   - VerifierError          3400–3499  (stellar_confidential::verifier)
 *   - ConfidentialTokenError 3500–3599  (stellar_confidential)
 *   - ComplianceError        3600–3699  (stellar_confidential::compliance)
 */

export const CONTRACT_ERRORS: Readonly<Record<number, string>> = {
  // Crypto (Grumpkin point decoding)
  1403: "Invalid point encoding: neither the identity nor a canonical on-curve point.",
  // Access control
  2000: "Not authorized: this account lacks the required role.",
  2001: "The contract admin is not set.",
  2002: "Role member index out of bounds.",
  2003: "The admin role for this role was not found.",
  2004: "The role still has members.",
  2005: "Role not found.",
  2006: "The contract admin is already set.",
  2007: "This account does not hold the role.",
  2008: "The role has no members.",
  2009: "An admin transfer is already in progress.",
  2010: "The maximum number of roles has been reached.",
  // Ownable
  2100: "This contract has no owner set.",
  2101: "An ownership transfer is already in progress.",
  2102: "The owner is already set.",
  // Role transfer (admin / ownership handover)
  2200: "There is no pending transfer to accept.",
  2201: "The transfer's expiry ledger is invalid.",
  2202: "This account is not the pending transfer recipient.",
  2203: "The pending transfer has expired.",
  // Auditor registry
  3300: "An auditor is already registered under this id.",
  3301: "No auditor is registered under this id.",
  3302: "The auditor key is the identity point.",
  3303: "The auditor key is not on the Grumpkin curve.",
  // Verifier registry
  3400: "A verification key is already registered for this circuit.",
  3401: "No verification key is registered for this circuit.",
  3402: "Zero-knowledge proof verification failed (verifier).",
  3403: "The verification key is malformed.",
  // Confidential token
  3500: "This account is already registered.",
  3501: "Account is not registered — register a confidential balance before transacting.",
  3502: "Amount must be non-negative.",
  3503: "A spender delegation already exists.",
  3504: "Spender delegation not found.",
  3505: "Spender delegation has expired.",
  3506: "Zero-knowledge proof verification failed.",
  3507: "Invalid operation data.",
  3508: "The token's underlying asset is not configured.",
  3509: "The token's verifier is not configured.",
  3510: "The token's auditor is not configured.",
  3511: "The token's address-as-field is not set.",
  3512: "The token's address-as-field is already set.",
  3513: "The token's underlying asset is already set.",
  3514: "Non-canonical point encoding.",
  // Compliance (stellar_confidential::compliance)
  3600: "Compliance is not configured for this token.",
  3601: "This account is frozen and cannot transact. Ask the token admin to unfreeze it.",
  3602:
    "This account is not permitted by the token's compliance policy (allowlist). Ask the admin to allow it.",
  3603: "This account is not authorized by the underlying asset.",
  3604: "Clawback requires the account to be frozen first.",
  3605: "The clawback amount must be strictly positive.",
  3606: "The clawback destination cannot be the token contract itself.",
};

const CONTRACT_CODE_RE = /Error\(Contract,\s*#(\d+)\)/;

/** The contract error code embedded in a raw HostError string, or `null`. */
export function parseContractErrorCode(raw: string): number | null {
  const m = CONTRACT_CODE_RE.exec(raw);
  return m ? Number(m[1]) : null;
}

/**
 * Translate a raw error string to a friendly message when it carries a known
 * contract error code; otherwise `null` (caller falls back to the raw text).
 */
export function humanizeContractError(raw: string): string | null {
  const code = parseContractErrorCode(raw);
  if (code === null) return null;
  return CONTRACT_ERRORS[code] ?? `The contract rejected the operation (error #${code}).`;
}
