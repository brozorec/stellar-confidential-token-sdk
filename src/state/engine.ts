/**
 * State reconstruction from the contract event stream.
 *
 * Replays confidential-token events to recover the local openings (`v`, `r`) of
 * an account's spendable and receiving balances — the secrets needed to build
 * the next proof. Events come from the hybrid source (`chain/event-source.ts`):
 * the RPC `getEvents` API for the recent tail, plus an optional Goldsky indexer
 * for history older than the RPC's ~7-day retention window.
 *
 * Reconstruction rules (owner = `state.address`; docs/protocol/wallet-state.md):
 *   - register(me)              → mark registered.
 *   - deposit(_, me)            → receiving += (amount, 0)   [deposits carry r = 0].
 *   - transfer(other, me)       → ECDH-decrypt (v_transfer, r_transfer); receiving += both.
 *   - spender_transfer(_, _, me)→ the same, keyed by the new allowance salt σ_a′.
 *   - merge(me)                 → spendable += receiving; receiving = (0, 0).
 *   - withdraw(me, _)           → spendable = open(b_tilde, sigma)  [checkpoint].
 *   - transfer(me, _)           → spendable = open(b_tilde, sigma)  [checkpoint].
 *   - set_spender(me, _)        → spendable = open(b_tilde, sigma)  [checkpoint].
 *   - revoke_spender(me, sp)    → spendable += (v_a, r_a) from (a_tilde, salt) under dvk.
 *   - clawback(me)              → spendable = spendable + receiving − (amount, 0);
 *                                 receiving = (0, 0).
 * Blindings accumulate mod p (the Grumpkin group order) in every fold.
 *
 * Checkpoints overwrite the spendable side, so a client that missed events
 * before the latest one still converges there. Everything else ACCUMULATES:
 * the receiving balance is a running sum since the last merge/clawback, and
 * merge, revoke_spender and clawback after the latest checkpoint are folded on
 * top of it — so every one of those events must be replayed, in order. With
 * RPC alone they are only recoverable inside the ~7-day window, so a client
 * must persist state and sync at least once per retention period; a
 * revoke_spender that ages out is lost permanently (its `a_tilde`/salt survive
 * nowhere else once the delegation is deleted — docs/sdk/wallet.md#recovery).
 * A configured indexer lifts this for a fresh client.
 *
 * Event application here is NOT idempotent: ordering and deduplication are
 * discharged by the event source (`hybridFetchEvents` → `dedupeById`), and the
 * persisted cursor keeps a sync from re-applying what it already applied.
 * Every sync ends by re-committing the openings against the on-chain points
 * read at the synced ledger ({@link StateEngine.sync}), so a missed or
 * duplicated event surfaces as a {@link StateDivergedError}, not as a
 * plausible wrong balance.
 */

import { commit, ecdh, type Point } from "../crypto/grumpkin.js";
import { fpAdd } from "../crypto/field.js";
import { DOMAIN } from "../crypto/constants.js";
import { addressToField } from "../crypto/address.js";
import {
  decryptWithDomain,
  deriveSpendR,
  deriveTransferBlind,
  dvkFromVkOp,
} from "../crypto/poseidon2.js";
import { openAllowanceEntry, openAllowanceUnder } from "../crypto/delegation.js";
import type { KeyPair } from "../crypto/keys.js";
import type { ChainClient } from "../chain/client.js";
import { type ConfidentialEvent } from "../chain/events.js";
import { hybridFetchEvents } from "../chain/event-source.js";
import type { IndexerClient } from "../chain/indexer.js";
import type { StateStore } from "./store.js";
import { freshState, type AccountState, type Opening } from "./types.js";
import { DelegationUnreadableError, toAllowance, type Allowance } from "./spender.js";

export interface StateEngineConfig {
  client: ChainClient;
  store: StateStore;
  /** Owner's confidential key set (for ECDH decryption + balance opening). */
  keys: KeyPair;
  /** Owner's Stellar (G-) address (for event direction). */
  address: string;
  /**
   * Ledger to start the FIRST sync from (e.g. the contract deploy ledger).
   * When an {@link indexer} is provided this may predate the RPC retention
   * window — the hybrid source backfills the gap from the indexer.
   */
  fromLedger: number;
  /**
   * Optional Goldsky indexer for full-history backfill below the RPC's ~7-day
   * window. When omitted, sync is RPC-only (the original behavior): events
   * older than retention are unavailable.
   */
  indexer?: IndexerClient;
  /**
   * Ledgers before expiry at which {@link StateEngine.delegation} reports
   * `"expiring"` (default `DEFAULT_EXPIRY_WARNING_LEDGERS`).
   */
  expiryWarningLedgers?: number;
}

/**
 * The opening of `C_a + C_b`. Blindings accumulate mod p (the Grumpkin group
 * order), NOT mod r: the contract folds commitments by point addition, so the
 * sum opens to `(v_a + v_b, (r_a + r_b) mod p)`. See fpAdd.
 */
function addOpening(a: Opening, b: Opening): Opening {
  return { v: a.v + b.v, r: fpAdd(a.r, b.r) };
}

/** Result of re-committing the local openings against the on-chain points. */
export interface ConsistencyReport {
  ok: boolean;
  spendableOk: boolean;
  receivingOk: boolean;
}

/**
 * The local openings do not re-commit to the on-chain commitments. Says which
 * accumulator diverged — they have different causes (spendable: a missed
 * revoke/clawback/merge after the last checkpoint; receiving: a missed or
 * aged-out credit) — and carries the (saved) state for inspection. A diverged
 * spendable opening MUST NOT be proven against: the proof would fail on-chain
 * with InvalidProof (3506) at best.
 */
export class StateDivergedError extends Error {
  /**
   * The saved state. Non-enumerable: it holds the secret openings `(v, r)`,
   * which error serializers and trackers (JSON loggers, Sentry's extra error
   * data) would otherwise ship off-device.
   */
  declare readonly state: AccountState;

  constructor(
    readonly report: ConsistencyReport,
    state: AccountState,
  ) {
    const which = [!report.spendableOk && "spendable", !report.receivingOk && "receiving"]
      .filter(Boolean)
      .join(" and ");
    super(
      `local ${which} opening does not match the on-chain commitment for ${state.address} ` +
        `(synced to ledger ${state.syncedLedger}) — an event was missed or misapplied`,
    );
    this.name = "StateDivergedError";
    Object.defineProperty(this, "state", { value: state, enumerable: false });
  }
}

/**
 * Balance reads one {@link StateEngine.sync} spends trying to read the
 * balance at the ledger its events were fetched through, before giving up.
 */
const MAX_BALANCE_READS = 5;

/**
 * The local openings differ from an on-chain balance read at a different
 * ledger than the one the events were synced through, so the difference may
 * be events the sync has not seen yet, or a lagging RPC node — not evidence of
 * a missed event. Nothing was verified either way: sync and retry. Carries no
 * openings.
 */
export class StateUnverifiedError extends Error {
  constructor(
    readonly address: string,
    readonly syncedLedger: number,
    readonly balanceLedger: number,
    advice: string,
  ) {
    super(
      `could not verify ${address}: the local openings differ from the balance read at ledger ` +
        `${balanceLedger}, but events are synced through ledger ${syncedLedger} — ${advice}`,
    );
    this.name = "StateUnverifiedError";
  }
}

export class StateEngine {
  constructor(private cfg: StateEngineConfig) {}

  /**
   * Recover an incoming transfer's amount and blinding from its event. For a
   * `spender_transfer`, pass the event's `sigmaANew` as `sigma`.
   */
  decryptIncoming(
    rE: Point,
    vTilde: bigint,
    sigma: bigint,
  ): { vTransfer: bigint; rTransfer: bigint } {
    const s = ecdh(this.cfg.keys.vk, rE);
    const vTransfer = decryptWithDomain(vTilde, DOMAIN.TRANSFER_AMOUNT, s, sigma);
    const rTransfer = deriveTransferBlind(s, sigma);
    return { vTransfer, rTransfer };
  }

  /** Recover the owner's post-op spendable opening from an emitted b_tilde. */
  openSpendable(bTilde: bigint, sigma: bigint): Opening {
    const v = decryptWithDomain(bTilde, DOMAIN.ENCRYPTED_BALANCE, this.cfg.keys.vk, sigma);
    const r = deriveSpendR(this.cfg.keys.vk, sigma);
    return { v, r };
  }

  /**
   * Recover a delegation's allowance opening `(v_a, r_a)` from a
   * `revoke_spender` event's `(a_tilde, allowance_salt)`, under
   * `dvk = Poseidon2(DELEGATION_VIEWING_KEY, vk, addr_f(spender))`.
   */
  openAllowance(spender: string, aTilde: bigint, allowanceSalt: bigint): Opening {
    return openAllowanceUnder(this.delegationKey(spender), aTilde, allowanceSalt);
  }

  /** The owner's `dvk` for a delegation to `spender`. */
  private delegationKey(spender: string): bigint {
    return dvkFromVkOp(this.cfg.keys.vk, addressToField(spender));
  }

  /**
   * The allowance currently escrowed with `spender`, read from the on-chain
   * delegation entry and opened under the owner's own `dvk`, or `null` if
   * none exists. Expired entries are returned: their value comes back on
   * `revoke_spender`. A spender_transfer moves it without touching the owner's
   * accumulators, so this is the only owner-side view of it.
   *
   * @throws {DelegationUnreadableError} if the entry does not re-commit
   *   under the owner's `dvk`: these keys did not create it.
   */
  async delegation(spender: string): Promise<Allowance | null> {
    const { address, client, expiryWarningLedgers } = this.cfg;
    const { delegation, latestLedger } = await client.spenderDelegationAt(address, spender);
    if (!delegation) return null;
    const dvk = this.delegationKey(spender);
    const opening = openAllowanceEntry(dvk, delegation);
    if (!opening) throw new DelegationUnreadableError(address, spender);
    return toAllowance(address, spender, delegation, dvk, opening, latestLedger, expiryWarningLedgers);
  }

  /** Apply one event in-place to `state`. */
  private apply(state: AccountState, ev: ConfidentialEvent): void {
    const me = state.address;
    switch (ev.type) {
      case "register":
        if (ev.account === me) state.registered = true;
        break;
      case "deposit":
        if (ev.to === me) state.receiving.v += ev.amount;
        break;
      case "merge":
        if (ev.account === me) {
          state.spendable = addOpening(state.spendable, state.receiving);
          state.receiving = { v: 0n, r: 0n };
        }
        break;
      case "withdraw":
        if (ev.from === me) state.spendable = this.openSpendable(ev.bTilde, ev.sigma);
        break;
      case "transfer":
        // A self-transfer applies in both roles: the sender side overwrites
        // spendable, the recipient side credits receiving.
        if (ev.from === me) state.spendable = this.openSpendable(ev.bTilde, ev.sigma);
        if (ev.to === me) this.credit(state, this.decryptIncoming(ev.rE, ev.vTilde, ev.sigma));
        break;
      case "set_spender":
        if (ev.account === me) state.spendable = this.openSpendable(ev.bTilde, ev.sigma);
        break;
      case "spender_transfer":
        // The owner (`from`) is untouched: the value left its C_spend at
        // set_spender. Pads are keyed by σ_a′, not the consumed salt.
        if (ev.to === me) this.credit(state, this.decryptIncoming(ev.rE, ev.vTilde, ev.sigmaANew));
        break;
      case "revoke_spender":
        // C_spend += C_a: fold, not a checkpoint.
        if (ev.account === me) {
          const a = this.openAllowance(ev.spender, ev.aTilde, ev.allowanceSalt);
          state.spendable = addOpening(state.spendable, a);
        }
        break;
      case "clawback":
        // C_spend' = C_spend + C_receive − amount·G; C_receive' = O
        // (compliance/storage.rs::clawback): the merge rule, then − amount.
        if (ev.account === me) {
          state.spendable = addOpening(state.spendable, {
            v: state.receiving.v - ev.amount,
            r: state.receiving.r,
          });
          state.receiving = { v: 0n, r: 0n };
        }
        break;
    }
    state.syncedLedger = Math.max(state.syncedLedger, ev.ledger);
  }

  private credit(state: AccountState, inc: { vTransfer: bigint; rTransfer: bigint }): void {
    state.receiving = addOpening(state.receiving, { v: inc.vTransfer, r: inc.rTransfer });
  }

  /** One fetch-apply-persist pass from the stored cursor. */
  private async syncOnce(): Promise<AccountState> {
    const prior = await this.cfg.store.load(this.cfg.address);
    const state = prior ?? freshState(this.cfg.address);

    const { events, cursor, latestLedger } = await hybridFetchEvents(
      this.cfg.client,
      this.cfg.indexer,
      { fromLedger: this.cfg.fromLedger, startCursor: state.cursor },
    );

    // Without a resume cursor the next pass (an incremental re-sync in sync(),
    // or the next sync) would re-fetch from the old position and re-apply these events,
    // and apply is not idempotent. Nothing is mutated or saved yet.
    if (events.length > 0 && !cursor) {
      throw new Error(
        `event source returned ${events.length} event(s) but no resume cursor; ` +
          "refusing to apply them, since a later sync would apply them again",
      );
    }

    for (const ev of events) this.apply(state, ev);
    if (cursor) state.cursor = cursor;
    state.syncedLedger = Math.max(state.syncedLedger, latestLedger);

    await this.cfg.store.save(state);
    return state;
  }

  /**
   * Sync from the last cursor (or `fromLedger` on first run), applying every
   * relevant event, persist, then verify the openings against the chain
   * (docs/sdk/wallet.md#consistency-checking). Returns the updated state.
   *
   * A match verifies the openings at whatever ledger the balance was read —
   * the commitments bind them. A mismatch only proves divergence when the read
   * ran at the ledger the events were fetched through (`state.syncedLedger`).
   * A mismatching read ahead of it means events landed after the fetch: sync
   * incrementally from the cursor and read again. One behind it is a lagging
   * RPC node: read again, without re-fetching. At most
   * {@link MAX_BALANCE_READS} reads.
   *
   * @throws {StateDivergedError} if the openings do not re-commit to the
   *   on-chain points read at the synced ledger. The state is persisted
   *   regardless.
   * @throws {StateUnverifiedError} if no mismatching read lands on the synced
   *   ledger — a busy account or a flaky RPC, not a divergence; retry.
   */
  async sync(): Promise<AccountState> {
    let state = await this.syncOnce();
    let { report, ledger } = await this.check(state);
    for (let reads = 1; !report.ok && ledger !== state.syncedLedger; reads++) {
      if (reads === MAX_BALANCE_READS) {
        throw new StateUnverifiedError(
          state.address,
          state.syncedLedger,
          ledger,
          `gave up after ${reads} balance reads; retry the sync`,
        );
      }
      if (ledger > state.syncedLedger) state = await this.syncOnce();
      ({ report, ledger } = await this.check(state));
    }
    if (!report.ok) throw new StateDivergedError(report, state);
    return state;
  }

  /** Read current state without syncing (or a fresh zero-state). */
  async current(): Promise<AccountState> {
    return (await this.cfg.store.load(this.cfg.address)) ?? freshState(this.cfg.address);
  }

  /**
   * The spendable opening to build a proof from, verified against the chain
   * first (docs/sdk/wallet.md#consistency-checking: "before constructing any
   * proof"). Only the spendable accumulator gates proving — the withdraw,
   * transfer and set_spender circuits open `C_spend` alone; a receiving
   * divergence is still reported on the error if both diverged.
   *
   * @throws {StateDivergedError} if the spendable opening does not match
   *   on-chain `C_spend` read at the ledger the state is synced to.
   * @throws {StateUnverifiedError} if it does not match a read at another
   *   ledger — usually events the state has not seen yet: {@link sync} first.
   */
  async spendableForProof(): Promise<Opening> {
    const state = await this.current();
    const { report, ledger } = await this.check(state);
    if (report.spendableOk) return { ...state.spendable };
    if (ledger !== state.syncedLedger) {
      throw new StateUnverifiedError(state.address, state.syncedLedger, ledger, "sync() before proving");
    }
    throw new StateDivergedError(report, state);
  }

  /**
   * Optimistically overwrite the cached spendable opening after a successful
   * owner op, avoiding a round-trip wait for the event to land. A later
   * {@link sync} reconciles against the chain.
   */
  async setSpendable(next: Opening): Promise<AccountState> {
    const state = await this.current();
    state.spendable = { ...next };
    await this.cfg.store.save(state);
    return state;
  }

  /**
   * Strong correctness check: the cached openings must re-commit to the exact
   * points stored on-chain. Mismatch means the local state diverged (a missed
   * event, an expired credit, or a bug) and is unsafe to spend from. An
   * account with no on-chain record is consistent only with a state that has
   * never seen its registration and holds zero openings. A failed on-chain read
   * propagates as-is — it is never reported as a divergence. One read, at
   * whatever ledger the RPC serves: unlike {@link sync}, a mismatch here is not
   * lined up with the ledger the state is synced to.
   */
  async verifyAgainstChain(): Promise<ConsistencyReport> {
    return (await this.check(await this.current())).report;
  }

  /** Compare against one balance read; `ledger` is the ledger it ran against. */
  private async check(state: AccountState): Promise<{ report: ConsistencyReport; ledger: number }> {
    const { account: onchain, latestLedger: ledger } = await this.cfg.client.confidentialBalanceAt(
      this.cfg.address,
    );
    if (!onchain) {
      const isZero = (o: Opening) => o.v === 0n && o.r === 0n;
      const spendableOk = !state.registered && isZero(state.spendable);
      const receivingOk = !state.registered && isZero(state.receiving);
      return { report: { ok: spendableOk && receivingOk, spendableOk, receivingOk }, ledger };
    }
    const spendableOk = commit(state.spendable.v, state.spendable.r).equals(onchain.spendableBalance);
    const receivingOk = commit(state.receiving.v, state.receiving.r).equals(onchain.receivingBalance);
    return { report: { ok: spendableOk && receivingOk, spendableOk, receivingOk }, ledger };
  }
}
