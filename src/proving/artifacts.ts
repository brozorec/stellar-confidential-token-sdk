/**
 * Circuit-artifact loading.
 *
 * The compiled ACIR circuits live in `circuits/<name>.json` (committed,
 * compiled by nargo 1.0.0-beta.11 from stellar-contracts v0.8.0; provenance
 * and sha256s in `circuits/manifest.json`). In the browser, import these JSON
 * files through the bundler and construct a {@link CircuitProver} directly. In
 * Node (scripts, tests) use {@link loadCircuit} below.
 *
 * `clawback` is shipped for auditor tooling; this SDK has no clawback witness
 * builder yet. Every other circuit has a builder in `witness/`.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { CompiledCircuit } from "@noir-lang/noir_js";

export type CircuitName =
  | "register"
  | "withdraw"
  | "transfer"
  | "set_spender"
  | "spender_transfer"
  | "clawback";

const circuitsDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "circuits");

/** Synchronously load a compiled circuit by name (Node only). */
export function loadCircuit(name: CircuitName): CompiledCircuit {
  const path = join(circuitsDir, `${name}.json`);
  return JSON.parse(readFileSync(path, "utf8")) as CompiledCircuit;
}
