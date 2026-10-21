/**
 * Token-admin operations (admin persona), for the upstream
 * `examples/confidential/compliant-token` and `allowlist-policy`
 * (stellar-contracts v0.8.0).
 *
 * Both contracts use `stellar_access::access_control` roles, not Ownable:
 *
 *   compliant token   freezer         freeze, unfreeze
 *                     config_manager  set_compliance_config
 *                     clawback        clawback, force_revoke_spender
 *   allowlist policy  manager         allow, disallow
 *
 * The token's constructor grants NONE of its roles: the admin must
 * {@link grantRole} each before the matching call can succeed (until then
 * every one fails with AccessControlError::Unauthorized, 2000). The allowlist
 * constructor grants `manager` to its `manager` argument. Every role-gated
 * entry point takes the authorizing role holder as its trailing `operator`
 * argument, and the signer must be that account.
 *
 * Membership lists (frozen accounts, allowed users) are reconstructed from the
 * contract's events by the dashboard — these helpers cover the point reads
 * and the mutations.
 */

import { xdr, Address, nativeToScVal, scValToNative } from "@stellar/stellar-sdk";

import type { ChainClient, Signer, InvokeResult } from "./client.js";
import { complianceConfigVal, type ComplianceConfig } from "./factory.js";
import { encodeClawbackData } from "./payload.js";

const addr = (a: string): xdr.ScVal => new Address(a).toScVal();
const sym = (s: string): xdr.ScVal => xdr.ScVal.scvSymbol(s);
const isVoid = (v: xdr.ScVal): boolean => v.switch().name === "scvVoid";

/** Role symbols of the compliant-token example. */
export const TOKEN_ROLES = {
  freezer: "freezer",
  configManager: "config_manager",
  clawback: "clawback",
} as const;

/** Role symbol of the allowlist-policy example (and the verifier/auditor registries). */
export const MANAGER_ROLE = "manager";

// ----- reads ---------------------------------------------------------------

/**
 * `get_admin() -> Option<Address>`: the access-control admin, or `null` when
 * none is set (renounced). Call failures propagate — a contract without
 * AccessControl is an error, not "no admin".
 */
export async function readAdmin(client: ChainClient, contractId: string): Promise<string | null> {
  const rv = await client.simulate(contractId, "get_admin", []);
  return isVoid(rv) ? null : Address.fromScVal(rv).toString();
}

/** `has_role(account, role) -> Option<u32>` (the member index when held). */
export async function hasRole(
  client: ChainClient,
  contractId: string,
  account: string,
  role: string,
): Promise<boolean> {
  return !isVoid(await client.simulate(contractId, "has_role", [addr(account), sym(role)]));
}

/** `is_frozen(account)` on a compliant token (`false` when compliance is unset). */
export async function isFrozen(client: ChainClient, tokenId: string, account: string): Promise<boolean> {
  return scValToNative(await client.simulate(tokenId, "is_frozen", [addr(account)])) === true;
}

/** `compliance_config() -> Option<ComplianceConfig>`, or `null` when unset. */
export async function readComplianceConfig(
  client: ChainClient,
  tokenId: string,
): Promise<ComplianceConfig | null> {
  const rv = await client.simulate(tokenId, "compliance_config", []);
  if (isVoid(rv)) return null;
  const m = new Map((rv.map() ?? []).map((e) => [e.key().sym().toString(), e.val()]));
  const policy = m.get("policy");
  const sac = m.get("sac_passthrough");
  if (sac === undefined) throw new Error("ComplianceConfig is missing sac_passthrough");
  return {
    ...(policy && !isVoid(policy) ? { policy: Address.fromScVal(policy).toString() } : {}),
    sacPassthrough: sac.b(),
  };
}

/**
 * `clawback_nonce(account) -> u32`: seizures executed against `account` so
 * far — the value the auditor binds into the next clawback proof.
 */
export async function clawbackNonce(client: ChainClient, tokenId: string, account: string): Promise<number> {
  return (await client.simulate(tokenId, "clawback_nonce", [addr(account)])).u32();
}

/** `allowed(account)` on an allowlist policy. */
export async function isAllowed(client: ChainClient, policyId: string, account: string): Promise<boolean> {
  return scValToNative(await client.simulate(policyId, "allowed", [addr(account)])) === true;
}

// ----- writes: roles (admin) -----------------------------------------------

/** `grant_role(account, role, caller)` — `caller` is the admin (or the role's admin). */
export function grantRole(
  client: ChainClient,
  signer: Signer,
  contractId: string,
  account: string,
  role: string,
  caller: string,
): Promise<InvokeResult> {
  return client.invoke(contractId, "grant_role", [addr(account), sym(role), addr(caller)], signer);
}

/** `revoke_role(account, role, caller)`. */
export function revokeRole(
  client: ChainClient,
  signer: Signer,
  contractId: string,
  account: string,
  role: string,
  caller: string,
): Promise<InvokeResult> {
  return client.invoke(contractId, "revoke_role", [addr(account), sym(role), addr(caller)], signer);
}

// ----- writes: compliance (role-gated) -------------------------------------

/** `freeze(account, operator)` — `operator` holds `freezer`. */
export function freezeAccount(
  client: ChainClient,
  signer: Signer,
  tokenId: string,
  account: string,
  operator: string,
): Promise<InvokeResult> {
  return client.invoke(tokenId, "freeze", [addr(account), addr(operator)], signer);
}

/** `unfreeze(account, operator)` — `operator` holds `freezer`. */
export function unfreezeAccount(
  client: ChainClient,
  signer: Signer,
  tokenId: string,
  account: string,
  operator: string,
): Promise<InvokeResult> {
  return client.invoke(tokenId, "unfreeze", [addr(account), addr(operator)], signer);
}

/** `set_compliance_config(config, operator)` — `operator` holds `config_manager`. */
export function setComplianceConfig(
  client: ChainClient,
  signer: Signer,
  tokenId: string,
  config: ComplianceConfig,
  operator: string,
): Promise<InvokeResult> {
  return client.invoke(
    tokenId,
    "set_compliance_config",
    [complianceConfigVal(config), addr(operator)],
    signer,
  );
}

/**
 * `force_revoke_spender(account, spender, operator)` — `operator` holds
 * `clawback`; `account` must be frozen (3604 otherwise). Folds the delegation's
 * escrowed allowance back into `C_spend`, where {@link clawback} can reach it.
 */
export function forceRevokeSpender(
  client: ChainClient,
  signer: Signer,
  tokenId: string,
  account: string,
  spender: string,
  operator: string,
): Promise<InvokeResult> {
  return client.invoke(
    tokenId,
    "force_revoke_spender",
    [addr(account), addr(spender), addr(operator)],
    signer,
  );
}

/**
 * `clawback(account, amount, destination, data, operator)` — `operator` holds
 * `clawback`; `account` must be frozen and `amount > 0`. `proof` is a clawback
 * circuit proof from the account's AUDITOR (it binds `destination` and the
 * account's {@link clawbackNonce}); this SDK does not build that witness yet.
 * `destination` undefined leaves the seized underlying in the pool.
 */
export function clawback(
  client: ChainClient,
  signer: Signer,
  tokenId: string,
  account: string,
  amount: bigint,
  destination: string | undefined,
  proof: Uint8Array,
  operator: string,
): Promise<InvokeResult> {
  return client.invoke(
    tokenId,
    "clawback",
    [
      addr(account),
      nativeToScVal(amount, { type: "i128" }),
      destination ? addr(destination) : xdr.ScVal.scvVoid(),
      encodeClawbackData(proof),
      addr(operator),
    ],
    signer,
  );
}

// ----- writes: allowlist policy (manager) ----------------------------------

/** `allow(account, operator)` on an allowlist policy — `operator` holds `manager`. */
export function allowUser(
  client: ChainClient,
  signer: Signer,
  policyId: string,
  account: string,
  operator: string,
): Promise<InvokeResult> {
  return client.invoke(policyId, "allow", [addr(account), addr(operator)], signer);
}

/** `disallow(account, operator)` on an allowlist policy — `operator` holds `manager`. */
export function disallowUser(
  client: ChainClient,
  signer: Signer,
  policyId: string,
  account: string,
  operator: string,
): Promise<InvokeResult> {
  return client.invoke(policyId, "disallow", [addr(account), addr(operator)], signer);
}
