/**
 * Spender-side wallet (docs/sdk/wallet.md#spender-side-wallet).
 *
 * A spender's state is the owner's on-chain `SpenderDelegation` entry, not an
 * event replay: `dvk` is recovered from the entry's `escrowed_dvk` by ECDH
 * under the spender's own `sk` ({@link recoverEscrowedDvk}), and the current
 * allowance `(v_a, r_a)` from its `(a_tilde, allowance_salt)`. Every read
 * re-commits that opening against the entry's `C_a`, so a returned allowance
 * is verified against chain state by construction, and nothing is persisted.
 *
 * Expiry is surfaced, never hidden: an expired entry is returned with
 * `status: "expired"` because its value stays escrowed until the owner
 * revokes (docs/protocol/account-state.md#spender-delegation). Only
 * {@link SpenderWallet.allowanceForProof} refuses it, since the contract
 * would reject the spend with `DelegationExpired` (3505). The contract
 * accepts a spend while `ledger.sequence() ≤ live_until_ledger`, and a
 * transaction lands one ledger after the read at the earliest, so an entry
 * read at `live_until_ledger` itself is already expired. An absent entry
 * means the pair was never delegated or the owner folded it back with
 * `revoke_spender`.
 *
 * The spender's capability stops at the allowance: `dvk` is a one-way
 * derivative of the owner's `vk`, and nothing here reads the owner's
 * spendable balance.
 */

import type { Point } from "../crypto/grumpkin.js";
import type { KeyPair } from "../crypto/keys.js";
import { addressToField } from "../crypto/address.js";
import { recoverEscrowedDvk, type AllowanceOpening } from "../crypto/delegation.js";
import type { ChainClient, OnChainDelegation } from "../chain/client.js";
import { hybridFetchEvents } from "../chain/event-source.js";
import type { IndexerClient } from "../chain/indexer.js";

/**
 * Default warning horizon: 17 280 ledgers, about one day at Stellar's ~5 s
 * close time.
 */
export const DEFAULT_EXPIRY_WARNING_LEDGERS = 17_280;

/**
 * `live`: spendable. `expiring`: spendable, inside the warning horizon.
 * `expired`: escrowed, and no transaction can land by `liveUntilLedger`.
 */
export type DelegationStatus = "live" | "expiring" | "expired";

/** A delegation's current allowance, opened and checked against its `C_a`. */
export interface Allowance extends AllowanceOpening {
  owner: string;
  spender: string;
  /** Delegation viewing key: the private witness `dvk_i` of spender_transfer. */
  dvk: bigint;
  /** `σ_a`, the stored salt the opening is derived under. */
  sigmaA: bigint;
  /** On-chain `C_a`, which `commit(v, r)` equals. */
  cA: Point;
  liveUntilLedger: number;
  /** The ledger the entry was read at. */
  ledger: number;
  status: DelegationStatus;
  /**
   * `liveUntilLedger − ledger`: how many ledgers a spend can still land in.
   * `≤ 0` once expired.
   */
  ledgersRemaining: number;
}

/** No delegation entry for the pair: never set, or revoked. */
export class DelegationNotFoundError extends Error {
  constructor(
    readonly owner: string,
    readonly spender: string,
  ) {
    super(`no delegation from ${owner} to ${spender} (never set, or revoked)`);
    this.name = "DelegationNotFoundError";
  }
}

/**
 * No transaction can land by `live_until_ledger` any more: the delegation is
 * still escrowed, no longer spendable.
 */
export class DelegationExpiredError extends Error {
  constructor(
    readonly owner: string,
    readonly spender: string,
    readonly liveUntilLedger: number,
    readonly ledger: number,
  ) {
    super(
      `delegation from ${owner} to ${spender} is spendable only through ledger ${liveUntilLedger} ` +
        `(read at ${ledger}); the allowance stays escrowed until the owner revokes`,
    );
    this.name = "DelegationExpiredError";
  }
}

/**
 * The entry exists but does not open under these keys. On the spender side
 * the escrow is not addressed to them; on the owner side
 * (`StateEngine.delegation`) these keys did not create it. Either way the key
 * set may instead be bound to another contract. Never a transient condition.
 */
export class DelegationUnreadableError extends Error {
  constructor(
    readonly owner: string,
    readonly spender: string,
  ) {
    super(`delegation from ${owner} to ${spender} does not open under these keys`);
    this.name = "DelegationUnreadableError";
  }
}

/**
 * Expiry classification of an entry read at `ledger`. Expired from
 * `ledger = liveUntilLedger` on: the earliest a spend can land is `ledger + 1`.
 */
export function delegationStatus(
  liveUntilLedger: number,
  ledger: number,
  warningLedgers = DEFAULT_EXPIRY_WARNING_LEDGERS,
): DelegationStatus {
  if (ledger >= liveUntilLedger) return "expired";
  return liveUntilLedger - ledger <= warningLedgers ? "expiring" : "live";
}

/**
 * Shape an entry plus its verified opening into an {@link Allowance}. Shared
 * with the owner side (`StateEngine.delegation`), which opens the same entry
 * under its own derivation of `dvk`.
 */
export function toAllowance(
  owner: string,
  spender: string,
  entry: OnChainDelegation,
  dvk: bigint,
  opening: AllowanceOpening,
  ledger: number,
  warningLedgers = DEFAULT_EXPIRY_WARNING_LEDGERS,
): Allowance {
  return {
    owner,
    spender,
    dvk,
    v: opening.v,
    r: opening.r,
    sigmaA: entry.allowanceSalt,
    cA: entry.allowanceCommitment,
    liveUntilLedger: entry.liveUntilLedger,
    ledger,
    status: delegationStatus(entry.liveUntilLedger, ledger, warningLedgers),
    ledgersRemaining: entry.liveUntilLedger - ledger,
  };
}

export interface SpenderWalletConfig {
  client: ChainClient;
  /** The spender's own contract-bound key set (it is a registered account). */
  keys: KeyPair;
  /** The spender's Stellar address (`op_i` is its address-as-field). */
  address: string;
  /** Ledgers before expiry at which `status` becomes `"expiring"`. */
  expiryWarningLedgers?: number;
}

export class SpenderWallet {
  constructor(private cfg: SpenderWalletConfig) {}

  /**
   * The current allowance `owner` delegated to this spender, or `null` if
   * no entry exists. Expired entries are returned (see the module docs).
   *
   * @throws {DelegationUnreadableError} if the entry does not open under
   *   these keys.
   */
  async allowance(owner: string): Promise<Allowance | null> {
    const { client, keys, address } = this.cfg;
    const { delegation, latestLedger } = await client.spenderDelegationAt(owner, address);
    if (!delegation) return null;
    const rec = recoverEscrowedDvk(keys.sk, addressToField(address), delegation);
    if (!rec) throw new DelegationUnreadableError(owner, address);
    return toAllowance(owner, address, delegation, rec.dvk, rec.opening, latestLedger, this.cfg.expiryWarningLedgers);
  }

  /**
   * The allowance to build a spender_transfer from, read and verified
   * immediately before proving. Pass it as `allowance` to
   * `buildSpenderTransferWitness`; it opens the on-chain `C_a` at the read
   * ledger. A delegation that expires before the transaction lands still
   * fails on-chain with `DelegationExpired` (3505): check `ledgersRemaining`.
   *
   * @throws {DelegationNotFoundError} if no entry exists.
   * @throws {DelegationExpiredError} if the read ledger has reached
   *   `liveUntilLedger`, so no transaction can land in time.
   * @throws {DelegationUnreadableError} if it does not open under these keys.
   */
  async allowanceForProof(owner: string): Promise<Allowance> {
    const a = await this.allowance(owner);
    if (!a) throw new DelegationNotFoundError(owner, this.cfg.address);
    if (a.status === "expired") {
      throw new DelegationExpiredError(owner, this.cfg.address, a.liveUntilLedger, a.ledger);
    }
    return a;
  }

  /**
   * Discover the owners that delegated to this spender from `set_spender`
   * events since `fromLedger`, and read each one's current allowance. Owners
   * whose entry is gone (revoked) are left out. With RPC alone only
   * `set_spender` events inside the ~7-day window are found; pass an
   * `indexer` for older delegations, or call {@link allowance} with a known
   * owner.
   */
  async allowances(opts: { fromLedger: number; indexer?: IndexerClient }): Promise<Allowance[]> {
    const { events } = await hybridFetchEvents(this.cfg.client, opts.indexer, { fromLedger: opts.fromLedger });
    const owners = new Set<string>();
    for (const ev of events) {
      if (ev.type === "set_spender" && ev.spender === this.cfg.address) owners.add(ev.account);
    }
    const out: Allowance[] = [];
    for (const owner of owners) {
      const a = await this.allowance(owner);
      if (a) out.push(a);
    }
    return out;
  }
}
