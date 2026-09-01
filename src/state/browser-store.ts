/**
 * Browser {@link StateStore} backed by `localStorage`. Safe to bundle (guards
 * for the absence of `localStorage` so it no-ops under SSR).
 *
 * Adequate for light use; a production wallet would prefer IndexedDB and
 * encryption at rest, since the cached openings are spending secrets.
 */

import type { AccountState } from "./types.js";
import { bigintReplacer, reviveState, type StateStore } from "./store.js";

export class LocalStorageStore implements StateStore {
  constructor(private prefix = "ctd:state:") {}

  #key(address: string): string {
    return this.prefix + address;
  }

  async load(address: string): Promise<AccountState | null> {
    if (typeof localStorage === "undefined") return null;
    const raw = localStorage.getItem(this.#key(address));
    return raw ? reviveState(JSON.parse(raw) as Record<string, unknown>) : null;
  }

  async save(state: AccountState): Promise<void> {
    if (typeof localStorage === "undefined") return;
    localStorage.setItem(this.#key(state.address), JSON.stringify(state, bigintReplacer));
  }
}
