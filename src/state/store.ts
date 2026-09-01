/**
 * Pluggable persistence for reconstructed account state. Local persistence is
 * load-bearing for correctness, not just performance: once an event ages out of
 * the RPC's ~7-day window, the cached openings are the ONLY way to keep the
 * balance spendable.
 *
 * This module is environment-neutral (no Node built-ins) so it is safe to
 * bundle for the browser. {@link MemoryStore} works everywhere;
 * {@link LocalStorageStore} (browser-store.ts) persists in `localStorage`; the
 * Node-only {@link JsonFileStore} lives in json-store.ts.
 */

import type { AccountState } from "./types.js";

export interface StateStore {
  load(address: string): Promise<AccountState | null>;
  save(state: AccountState): Promise<void>;
}

/** JSON replacer: serialize bigints as `0x…` strings. */
export function bigintReplacer(_key: string, value: unknown): unknown {
  return typeof value === "bigint" ? `0x${value.toString(16)}` : value;
}

/** Rebuild an {@link AccountState} from its JSON form (bigints as `0x…`). */
export function reviveState(raw: Record<string, unknown>): AccountState {
  const op = (o: { v: string; r: string }): { v: bigint; r: bigint } => ({
    v: BigInt(o.v),
    r: BigInt(o.r),
  });
  return {
    address: raw.address as string,
    spendable: op(raw.spendable as { v: string; r: string }),
    receiving: op(raw.receiving as { v: string; r: string }),
    registered: raw.registered as boolean,
    cursor: raw.cursor as string | undefined,
    syncedLedger: raw.syncedLedger as number,
  };
}

export function cloneState(s: AccountState): AccountState {
  return {
    address: s.address,
    spendable: { ...s.spendable },
    receiving: { ...s.receiving },
    registered: s.registered,
    cursor: s.cursor,
    syncedLedger: s.syncedLedger,
  };
}

/** Ephemeral in-memory store (tests, single-run scripts). */
export class MemoryStore implements StateStore {
  #byAddress = new Map<string, AccountState>();

  async load(address: string): Promise<AccountState | null> {
    const s = this.#byAddress.get(address);
    return s ? cloneState(s) : null;
  }
  async save(state: AccountState): Promise<void> {
    this.#byAddress.set(state.address, cloneState(state));
  }
}
