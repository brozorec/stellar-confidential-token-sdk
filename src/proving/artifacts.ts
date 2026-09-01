/**
 * Circuit-artifact loading.
 *
 * The compiled ACIR circuits live in `circuits/<name>.json` (committed,
 * produced by nargo 1.0.0-beta.9). In the browser, import these JSON files
 * through the bundler and construct a {@link CircuitProver} directly. In
 * Node (scripts, tests) use {@link loadCircuit} below.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { CompiledCircuit } from "@noir-lang/noir_js";

export type CircuitName = "register" | "withdraw" | "transfer";

const circuitsDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "circuits");

/** Synchronously load a compiled circuit by name (Node only). */
export function loadCircuit(name: CircuitName): CompiledCircuit {
  const path = join(circuitsDir, `${name}.json`);
  return JSON.parse(readFileSync(path, "utf8")) as CompiledCircuit;
}
