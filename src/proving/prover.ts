/**
 * UltraHonk proving via `bb.js`, driven by a `noir_js`-solved witness.
 *
 * Keccak transcript is MANDATORY: the on-chain `ultrahonk-soroban-verifier`
 * (NethermindEth/rs-soroban-ultrahonk) uses a keccak256 Fiat-Shamir transcript,
 * so every proof must be generated and verified with `{ keccak: true }`. A
 * Poseidon-transcript proof (the bb.js default) silently fails on-chain. The
 * off-chain disclosure circuits use the same transcript in the ZK flavour
 * (`{ zk: true }`, see {@link CircuitProverOptions}).
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

/**
 * Off-chain selective-disclosure proofs: the same keccak transcript, in the ZK
 * flavour. The on-chain verifier implements only the non-ZK flavour, which is
 * why the core circuits cannot use it; disclosure proofs are verified by bb.js
 * and handed to a third party that may archive them, while their witness holds
 * `sk`. The VK is byte-identical across the two flavours, so a VK pin cannot
 * tell them apart — a proof checked under the other flavour just fails.
 */
const KECCAK_ZK = { keccakZK: true } as const;

export interface CircuitProverOptions {
  /**
   * Prove and verify in the ZK flavour. Required for the disclosure circuits
   * (`circuits/disclosure/*.vk.json` records `"zk": true`); MUST stay off for
   * every circuit the on-chain verifier checks.
   */
  zk?: boolean;
}

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
  readonly #flavour: typeof KECCAK | typeof KECCAK_ZK;
  #backend?: UltraHonkBackend;
  #vk?: Uint8Array;
  /** Whether this prover uses the ZK flavour ({@link CircuitProverOptions.zk}). */
  readonly zk: boolean;

  constructor(circuit: CompiledCircuit, options: CircuitProverOptions = {}) {
    this.#noir = new Noir(circuit);
    this.#bytecode = circuit.bytecode;
    this.zk = options.zk === true;
    this.#flavour = this.zk ? KECCAK_ZK : KECCAK;
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
    const { proof, publicInputs } = await backend.generateProof(witness, this.#flavour);
    return { proof, publicInputs };
  }

  /**
   * Verify a proof locally. For on-chain circuits this is a sanity check (the
   * chain is the real authority); for disclosure circuits it is the verdict.
   */
  async verify(result: ProofResult): Promise<boolean> {
    const backend = await this.#backendInstance();
    return backend.verifyProof(result, this.#flavour);
  }

  /**
   * Derive this circuit's verification key (keccak transcript). Off-chain
   * disclosure verifiers compare these bytes against the pinned VK shipped in
   * `circuits/disclosure/` before trusting a verify result — the VK is the
   * cryptographic fingerprint of the circuit. Derived once per prover (it
   * depends only on the bytecode and flavour); each call returns a copy.
   */
  async verificationKey(): Promise<Uint8Array> {
    if (!this.#vk) {
      const backend = await this.#backendInstance();
      this.#vk = await backend.getVerificationKey(this.#flavour);
    }
    return this.#vk.slice();
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
  options?: CircuitProverOptions,
): CircuitProver {
  return new CircuitProver(artifact as unknown as CompiledCircuit, options);
}
