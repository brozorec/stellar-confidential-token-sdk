/**
 * Token-factory deploy helpers (advanced mode), for the upstream
 * `examples/confidential/factory` (stellar-contracts v0.8.0).
 *
 * The factory deploys the compliant token (`examples/confidential/
 * compliant-token`) and the allowlist policy (`examples/confidential/
 * allowlist-policy`) from WASM already uploaded on-chain — the hashes are
 * pinned in its constructor `(token_wasm_hash, allowlist_wasm_hash)`. The
 * browser only INVOKES these methods; it never installs WASM. The verifier and
 * auditor registries are passed per deployment, since tokens share them.
 *
 * Each deployed address is `sha256(xdr((constructor args, salt)))` in the
 * factory's namespace, so a configuration's address is bound to its
 * arguments, and the `u32` salt (passed last) only distinguishes several
 * deployments of one configuration. `predict*` returns that address without
 * deploying.
 *
 * Arg tuples mirror the factory's Rust signatures; keep them in sync with
 * `examples/confidential/factory/src/contract.rs`.
 */

import { xdr, Address } from "@stellar/stellar-sdk";

import type { ChainClient, Signer } from "./client.js";
import { scvStruct } from "./payload.js";

const addr = (a: string): xdr.ScVal => new Address(a).toScVal();
const u32 = (n: number): xdr.ScVal => xdr.ScVal.scvU32(n);

/**
 * `stellar_confidential::compliance::ComplianceConfig`: the token's optional
 * external policy, and whether every gate also consults the underlying SAC's
 * `authorized` view (traps unless the underlying IS a Stellar Asset Contract).
 */
export interface ComplianceConfig {
  policy?: string;
  sacPassthrough: boolean;
}

/** `ComplianceConfig` as its contracttype ScMap (`policy: None` → Void). */
export function complianceConfigVal(c: ComplianceConfig): xdr.ScVal {
  return scvStruct({
    policy: c.policy ? addr(c.policy) : xdr.ScVal.scvVoid(),
    sac_passthrough: xdr.ScVal.scvBool(c.sacPassthrough),
  });
}

/** A random `u32` deploy salt. */
export function randomSalt(): number {
  const s = new Uint32Array(1);
  crypto.getRandomValues(s);
  return s[0]!;
}

/** Constant collaborators every token deploy is wired to. */
export interface FactoryWiring {
  factory: string;
  underlying: string;
  verifier: string;
  auditor: string;
}

function requireAddr(rv: xdr.ScVal | undefined, method: string): string {
  if (!rv) throw new Error(`${method} returned no value`);
  return Address.fromScVal(rv).toString();
}

const tokenArgs = (w: FactoryWiring, admin: string, compliance: ComplianceConfig, salt: number) => [
  addr(admin),
  addr(w.underlying),
  addr(w.verifier),
  addr(w.auditor),
  complianceConfigVal(compliance),
  u32(salt),
];

/**
 * `deploy_token(admin, underlying_asset, verifier, auditor, compliance, salt)`
 * → compliant token address. The token grants no role at construction: the
 * `admin` must `grant_role` freezer / config_manager / clawback before any
 * admin call succeeds (see `admin.ts`).
 */
export async function deployToken(
  client: ChainClient,
  signer: Signer,
  w: FactoryWiring,
  admin: string,
  compliance: ComplianceConfig,
  salt: number = randomSalt(),
): Promise<string> {
  const r = await client.invoke(w.factory, "deploy_token", tokenArgs(w, admin, compliance, salt), signer);
  return requireAddr(r.returnValue, "deploy_token");
}

/** `deploy_allowlist(admin, manager, salt)` → allowlist policy address. */
export async function deployAllowlist(
  client: ChainClient,
  signer: Signer,
  factory: string,
  admin: string,
  manager: string,
  salt: number = randomSalt(),
): Promise<string> {
  const r = await client.invoke(
    factory,
    "deploy_allowlist",
    [addr(admin), addr(manager), u32(salt)],
    signer,
  );
  return requireAddr(r.returnValue, "deploy_allowlist");
}

export interface AllowlistAndTokenParams {
  policyAdmin: string;
  /** Granted the allowlist's `manager` role (allow / disallow). */
  policyManager: string;
  tokenAdmin: string;
  sacPassthrough: boolean;
}

/**
 * `deploy_allowlist_and_token(policy_admin, policy_manager, token_admin,
 * underlying_asset, verifier, auditor, sac_passthrough, salt)` →
 * `{ policy, token }`: a fresh allowlist and a compliant token whose
 * `compliance.policy` points at it, both under the same salt.
 */
export async function deployAllowlistAndToken(
  client: ChainClient,
  signer: Signer,
  w: FactoryWiring,
  p: AllowlistAndTokenParams,
  salt: number = randomSalt(),
): Promise<{ policy: string; token: string }> {
  const r = await client.invoke(
    w.factory,
    "deploy_allowlist_and_token",
    [
      addr(p.policyAdmin),
      addr(p.policyManager),
      addr(p.tokenAdmin),
      addr(w.underlying),
      addr(w.verifier),
      addr(w.auditor),
      xdr.ScVal.scvBool(p.sacPassthrough),
      u32(salt),
    ],
    signer,
  );
  const vec = r.returnValue?.vec();
  if (!vec || vec.length !== 2) {
    throw new Error("deploy_allowlist_and_token: expected a (policy, token) tuple");
  }
  return {
    policy: Address.fromScVal(vec[0]!).toString(),
    token: Address.fromScVal(vec[1]!).toString(),
  };
}

/** `predict_token_address(...)` — same arguments as {@link deployToken}. */
export async function predictTokenAddress(
  client: ChainClient,
  w: FactoryWiring,
  admin: string,
  compliance: ComplianceConfig,
  salt: number,
): Promise<string> {
  return requireAddr(
    await client.simulate(w.factory, "predict_token_address", tokenArgs(w, admin, compliance, salt)),
    "predict_token_address",
  );
}

/** `predict_allowlist_address(admin, manager, salt)`. */
export async function predictAllowlistAddress(
  client: ChainClient,
  factory: string,
  admin: string,
  manager: string,
  salt: number,
): Promise<string> {
  return requireAddr(
    await client.simulate(factory, "predict_allowlist_address", [addr(admin), addr(manager), u32(salt)]),
    "predict_allowlist_address",
  );
}
