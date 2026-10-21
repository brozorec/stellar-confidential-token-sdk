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
 * Every sync ends with {@link StateEngine.verifyAgainstChain}, so a missed or
 * duplicated event surfaces as a {@link StateDivergedError}, not as a
 * plausible wrong balance.
 */

import { commit, ecdh, type Point } from "../crypto/grumpkin.js";
import { fpAdd, frMod } from "../crypto/field.js";
import { DOMAIN } from "../crypto/constants.js";
import { addressToField } from "../crypto/address.js";
import {
  deriveAllowR,
  deriveSpendR,
  deriveTransferBlind,
  dvkFromVkOp,
  poseidonWithDomain,
} from "../crypto/poseidon2.js";
import type { KeyPair } from "../crypto/keys.js";
import type { ChainClient } from "../chain/client.js";
import { type ConfidentialEvent } from "../chain/events.js";
import { hybridFetchEvents } from "../chain/event-source.js";
import type { IndexerClient } from "../chain/indexer.js";
import type { StateStore } from "./store.js";
import { freshState, type AccountState, type Opening } from "./types.js";

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
  constructor(
    readonly report: ConsistencyReport,
    readonly state: AccountState,
  ) {
    const which = [!report.spendableOk && "spendable", !report.receivingOk && "receiving"]
      .filter(Boolean)
      .join(" and ");
    super(
      `local ${which} opening does not match the on-chain commitment for ${state.address} ` +
        `(synced to ledger ${state.syncedLedger}) — an event was missed or misapplied`,
    );
    this.name = "StateDivergedError";
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
    const vTransfer = frMod(vTilde - poseidonWithDomain(DOMAIN.TRANSFER_AMOUNT, [s, sigma]));
    const rTransfer = deriveTransferBlind(s, sigma);
    return { vTransfer, rTransfer };
  }

  /** Recover the owner's post-op spendable opening from an emitted b_tilde. */
  openSpendable(bTilde: bigint, sigma: bigint): Opening {
    const v = frMod(bTilde - poseidonWithDomain(DOMAIN.ENCRYPTED_BALANCE, [this.cfg.keys.vk, sigma]));
    const r = deriveSpendR(this.cfg.keys.vk, sigma);
    return { v, r };
  }

  /**
   * Recover a delegation's allowance opening `(v_a, r_a)` from a
   * `revoke_spender` event's `(a_tilde, allowance_salt)`, under
   * `dvk = Poseidon2(DELEGATION_VIEWING_KEY, vk, addr_f(spender))`.
   */
  openAllowance(spender: string, aTilde: bigint, allowanceSalt: bigint): Opening {
    const dvk = dvkFromVkOp(this.cfg.keys.vk, addressToField(spender));
    const v = frMod(aTilde - poseidonWithDomain(DOMAIN.ENCRYPTED_ALLOWANCE, [dvk, allowanceSalt]));
    return { v, r: deriveAllowR(dvk, allowanceSalt) };
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
        // Blindings accumulate mod p (the Grumpkin group order), NOT mod r:
        // the contract merges by point addition, so the resulting commitment
        // opens to (v_s + v_r, (r_s + r_r) mod p). See fpAdd.
        if (ev.account === me) {
          state.spendable = {
            v: state.spendable.v + state.receiving.v,
            r: fpAdd(state.spendable.r, state.receiving.r),
          };
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
          state.spendable = {
            v: state.spendable.v + a.v,
            r: fpAdd(state.spendable.r, a.r),
          };
        }
        break;
      case "clawback":
        // C_spend' = C_spend + C_receive − amount·G; C_receive' = O
        // (compliance/storage.rs::clawback): the merge rule, then − amount.
        if (ev.account === me) {
          state.spendable = {
            v: state.spendable.v + state.receiving.v - ev.amount,
            r: fpAdd(state.spendable.r, state.receiving.r),
          };
          state.receiving = { v: 0n, r: 0n };
        }
        break;
    }
    state.syncedLedger = Math.max(state.syncedLedger, ev.ledger);
  }

  private credit(state: AccountState, inc: { vTransfer: bigint; rTransfer: bigint }): void {
    state.receiving = {
      v: state.receiving.v + inc.vTransfer,
      r: fpAdd(state.receiving.r, inc.rTransfer),
    };
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
   * The on-chain read happens after the event fetch, so an event landing in
   * between can produce a spurious mismatch; one re-sync absorbs that before
   * a mismatch is reported.
   *
   * @throws {StateDivergedError} if the openings still do not re-commit to the
   *   on-chain points. The state is persisted regardless.
   */
  async sync(opts: { verify?: boolean } = {}): Promise<AccountState> {
    let state = await this.syncOnce();
    if (opts.verify === false) return state;
    let report = await this.verifyAgainstChain();
    if (!report.ok) {
      state = await this.syncOnce();
      report = await this.verifyAgainstChain();
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
   * proof"). Only the spendable accumulator gates proving — the withdraw and
   * transfer circuits open `C_spend` alone; a receiving divergence is still
   * reported on the error if both diverged.
   *
   * @throws {StateDivergedError} if the spendable opening does not match
   *   on-chain `C_spend` — sync again before retrying.
   */
  async spendableForProof(): Promise<Opening> {
    const report = await this.verifyAgainstChain();
    const state = await this.current();
    if (!report.spendableOk) throw new StateDivergedError(report, state);
    return { ...state.spendable };
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
   * never seen its registration and holds zero openings.
   */
  async verifyAgainstChain(): Promise<ConsistencyReport> {
    const state = await this.current();
    const onchain = await this.cfg.client.confidentialBalance(this.cfg.address);
    if (!onchain) {
      const isZero = (o: Opening) => o.v === 0n && o.r === 0n;
      const spendableOk = !state.registered && isZero(state.spendable);
      const receivingOk = !state.registered && isZero(state.receiving);
      return { ok: spendableOk && receivingOk, spendableOk, receivingOk };
    }
    const spendableOk = commit(state.spendable.v, state.spendable.r).equals(onchain.spendableBalance);
    const receivingOk = commit(state.receiving.v, state.receiving.r).equals(onchain.receivingBalance);
    return { ok: spendableOk && receivingOk, spendableOk, receivingOk };
  }
}
