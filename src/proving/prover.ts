/**
 * UltraHonk proving via `bb.js`, driven by a `noir_js`-solved witness.
 *
 * Keccak transcript is MANDATORY: the on-chain `ultrahonk-soroban-verifier`
 * (NethermindEth/rs-soroban-ultrahonk) uses a keccak256 Fiat-Shamir transcript,
 * so every proof must be generated and verified with `{ keccak: true }`. A
 * Poseidon-transcript proof (the bb.js default) silently fails on-chain.
 *
 * The contract reconstructs the public inputs from the submitted payload plus
 * on-chain state, so only the `proof` bytes travel on the wire; `publicInputs`
 * is returned here for local verification and debugging.
 *
 * bb.js is loaded through a pluggable async loader rather than a static import.
 * In Node (scripts, tests) the default loader imports `@aztec/bb.js` directly.
 * In a webpack/Next browser build that default is broken: bb.js spawns its wasm
 * Web Worker via `new Worker(new URL('./main.worker.js', import.meta.url))` with
 * a `webpackIgnore`, so once bundled into a hashed chunk the worker URL no
 * longer resolves and proving hangs. The browser app therefore overrides the
 * loader (see the app's lib/bb-loader.ts) to import bb.js as native ESM from a
 * stable public path where its sibling worker/wasm files stay intact.
 */

import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import type { UltraHonkBackend } from "@aztec/bb.js";

import type { NoirInputs } from "../witness/common.js";

/** Must match the on-chain verifier's transcript. */
const KECCAK = { keccak: true } as const;

type UltraHonkBackendCtor = new (
  bytecode: string,
  options?: { threads?: number },
) => UltraHonkBackend;

/** Default loader: a direct dynamic import. Correct under Node ESM. */
let loadUltraHonkBackend: () => Promise<UltraHonkBackendCtor> = async () =>
  (await import("@aztec/bb.js")).UltraHonkBackend as unknown as UltraHonkBackendCtor;

/**
 * Override how the `UltraHonkBackend` constructor is obtained. Browser bundlers
 * that cannot serve bb.js's worker assets must call this (typically pointing at
 * a native-ESM copy of bb.js's `dest/browser/`) before any proving happens.
 */
export function setUltraHonkBackendLoader(loader: () => Promise<UltraHonkBackendCtor>): void {
  loadUltraHonkBackend = loader;
}

export interface ProofResult {
  /** Raw UltraHonk proof bytes — this is what the contract receives. */
  proof: Uint8Array;
  /** Field-element public inputs (hex), as bb.js split them out. */
  publicInputs: string[];
}

/**
 * Wraps one circuit: a `Noir` solver and a lazily-created `UltraHonkBackend`.
 * Construct once per circuit and reuse — backend init loads WASM and the CRS,
 * which is expensive. Call `destroy()` when done.
 */
export class CircuitProver {
  readonly #noir: Noir;
  readonly #bytecode: string;
  #backend?: UltraHonkBackend;

  constructor(circuit: CompiledCircuit) {
    this.#noir = new Noir(circuit);
    this.#bytecode = circuit.bytecode;
  }

  async #backendInstance(): Promise<UltraHonkBackend> {
    if (!this.#backend) {
      const Backend = await loadUltraHonkBackend();
      this.#backend = new Backend(this.#bytecode);
    }
    return this.#backend;
  }

  /** Solve the witness from `inputs` and generate a keccak-transcript proof. */
  async prove(inputs: NoirInputs): Promise<ProofResult> {
    const { witness } = await this.#noir.execute(inputs);
    const backend = await this.#backendInstance();
    const { proof, publicInputs } = await backend.generateProof(witness, KECCAK);
    return { proof, publicInputs };
  }

  /** Locally verify a proof (sanity check; the chain is the real authority). */
  async verify(result: ProofResult): Promise<boolean> {
    const backend = await this.#backendInstance();
    return backend.verifyProof(result, KECCAK);
  }

  /**
   * Derive this circuit's verification key (keccak transcript). Off-chain
   * disclosure verifiers compare these bytes against the pinned VK shipped in
   * `circuits/disclosure/` before trusting a verify result — the VK is the
   * cryptographic fingerprint of the circuit.
   */
  async verificationKey(): Promise<Uint8Array> {
    const backend = await this.#backendInstance();
    return backend.getVerificationKey(KECCAK);
  }

  async destroy(): Promise<void> {
    await this.#backend?.destroy();
  }
}

/**
 * Build a {@link CircuitProver} from an imported circuit artifact (the JSON
 * produced by `nargo compile`). Lets callers pass a bundler-imported JSON
 * without depending on the noir `CompiledCircuit` type.
 */
export function proverFromArtifact(
  artifact: { bytecode: string } & Record<string, unknown>,
): CircuitProver {
  return new CircuitProver(artifact as unknown as CompiledCircuit);
}
