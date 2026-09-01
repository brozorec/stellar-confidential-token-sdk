/**
 * Node-only {@link StateStore} backed by a JSON file. Kept OUT of the package
 * barrel so the browser bundle never pulls in `node:fs`. Import it directly:
 * `import { JsonFileStore } from "stellar-confidential-token-sdk/state/json-store"`.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname } from "node:path";

import type { AccountState } from "./types.js";
import { bigintReplacer, reviveState, type StateStore } from "./store.js";

export class JsonFileStore implements StateStore {
  constructor(private path: string) {}

  #readAll(): Record<string, unknown> {
    if (!existsSync(this.path)) return {};
    return JSON.parse(readFileSync(this.path, "utf8")) as Record<string, unknown>;
  }

  async load(address: string): Promise<AccountState | null> {
    const raw = this.#readAll()[address] as Record<string, unknown> | undefined;
    return raw ? reviveState(raw) : null;
  }

  async save(state: AccountState): Promise<void> {
    const all = this.#readAll();
    all[state.address] = state;
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify(all, bigintReplacer, 2));
  }
}
