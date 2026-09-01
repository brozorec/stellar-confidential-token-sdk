# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
pnpm install
pnpm build              # tsc -> dist/ (also the `prepare` script)
pnpm typecheck          # tsc --noEmit
pnpm test:fast          # everything except UltraHonk proof generation (seconds)
pnpm test               # test:fast + prove.mjs + disclosure.mjs (slow, needs the bb.js CRS)
pnpm exec tsx test/<name>.mjs   # run one test
```

There is no linter and no test framework. Tests are plain `.mjs` scripts run under `tsx`; each keeps its own `pass`/`fail` counters and ends with `process.exit(fail === 0 ? 0 : 1)`. They import **`../src/*.ts` directly**, so `pnpm build` is not a prerequisite for running them.

`pnpm test` / `pnpm test:fast` are hand-maintained `&&` chains in `package.json` — a new test file runs in CI only once it is added to those chains. (`test/shape-filter.mjs` currently is not in either.)

Env-gated tests (`indexer-parity.mjs`, `shape-filter.mjs`) skip cleanly with exit 0 unless `CTD_INDEXER_URL` and `CTD_TOKEN` are set; `CTD_RPC_URL` and `CTD_FROM_LEDGER` are optional overrides. CI (`.github/workflows/ci.yml`) runs `test:fast` on every PR and the two proving tests on main pushes only.

## What this package is

The off-chain mirror of an on-chain system: Noir circuits (compiled artifacts in `circuits/`), a Soroban confidential-token contract, and an UltraHonk verifier contract. The circuits and the contract are **not in this repo** — the SDK reimplements their cryptography in TypeScript and pins that reimplementation with tests that execute the real compiled circuits.

Consequence for almost every change: most constants, field names, and orderings here are *contracts with code you cannot see from this repo*. A wrong value does not throw — it produces a proof that fails to verify on-chain, or a balance that silently diverges.

## Layers (`src/`)

Data flows `crypto → witness → proving → chain`, with `state`, `auditor`, and `disclosure` as consumers.

- **`crypto/`** — Grumpkin (`@noble/curves`) + Poseidon2 (raw permutation from `@zkpassport/poseidon2`, sponge re-implemented locally), key/address derivation. `constants.ts` holds generators, field moduli, and the 16 domain tags.
- **`witness/`** — one builder per circuit. Each returns `inputs` (Noir `main()` params, keyed by the circuit's exact parameter names), the on-chain `payload` struct, and any local follow-on state (`next` opening, `rEScalar`).
- **`proving/`** — `CircuitProver` wraps a `noir_js` solver + a lazily created `bb.js` `UltraHonkBackend`. Construct once per circuit and reuse; call
  `destroy()`.
- **`chain/`** — `ChainClient` (simulate / invoke / poll), `payload.ts` (XDR envelopes), `contract.ts` (per-entry-point submitters), `events.ts` (RPC event
  decode), `indexer.ts` (Goldsky JSON decode), `event-source.ts` (hybrid), plus `factory.ts`, `admin.ts`, `errors.ts` for the dashboard/admin personas.
- **`state/`** — `StateEngine` replays events into `{v, r}` openings behind a pluggable `StateStore`.
- **`auditor/`** — decrypts the auditor channels from a raw event + the auditor secret `k`. No holder cooperation needed.
- **`disclosure/`** — off-chain selective disclosure: holder proves, receiver
  verifies through a mandatory multi-step protocol.

## Invariants that must not drift

**Keccak transcript is mandatory.** Every proof is generated and verified with `{ keccak: true }` (`KECCAK` in `proving/prover.ts`) because the on-chain verifier uses keccak256 Fiat–Shamir. A default-transcript proof verifies locally and fails on-chain.

**Domain tags are the wire format.** `DOMAIN` in `crypto/constants.ts` is exactly `1n..16n`, distinct, one sponge mode each (11/12 are the two-squeeze tags). Tags 1–13 are absorbed on-chain or in-circuit; 14–16 are absorbed nowhere, so drift there breaks *cross-client* reads silently — nothing fails. `test/smoke.mjs` pins all sixteen; treat that test as the spec.

**`fpAdd` vs `frAdd`.** Blinding factors accumulate mod `p` (the Grumpkin group order, `FP_MODULUS`), values mod `r` (`FR_MODULUS`). Using `frAdd` on a blinding sum diverges by `p - r` about half the time and only surfaces as an on-chain commitment mismatch after a merge.

**Public-input order.** Each witness builder's docstring records the circuit's public-input order; `chain/payload.ts` encodes structs as `ScMap` with symbol keys **sorted ascending**, and a `Point` is a flat `BytesN<64>` (`be(x)||be(y)`, identity = 64 zero bytes) — never an `{x, y}` sub-map.

**Contract field names appear verbatim** in `chain/events.ts` (`buildConfidentialEvent`) and `chain/client.ts` (`parseAccount`). Both have deliberate completeness checks that turn a contract-side rename into a loud throw; keep them.

**One event shape, two decoders.** `buildConfidentialEvent` is the single shape definition; the RPC (XDR) and indexer (Goldsky JSON) paths only supply different `addr`/`EventDataAccessor` adapters. `test/indexer-parity.mjs` pins that the two decode byte-identically.

**Disclosure trust boundary** (`disclosure/verify.ts`): the only values taken from a bundle are `(R_disc, v_tilde_disc)` plus the event *reference*. Event fields, PVKs, and `addr_f` are re-resolved from chain state; `(P_R, nu)` come from the verifier's own request record. Widening what the bundle contributes voids the proof's meaning. The VK derived from the loaded circuit bytecode is also compared byte-for-byte against the pinned `circuits/disclosure/*.vk.json`.

## Event retention — the design's central constraint

Spendable secrets (`v`, `r`) live only in events; the chain stores commitments. Soroban RPC `getEvents` retains ~7 days.

`chain/event-source.ts` splits: the optional Goldsky indexer serves `[next, seam-1]`, the RPC serves `[seam, head]`, where `seam = rpcOldest + RPC_SEAM_MARGIN`. The ranges are disjoint by construction; `dedupeById` is a boundary guard, and its **stable sort by ledger only** is load-bearing because `StateEngine.apply` is order-sensitive and not idempotent.

A *configured* indexer's backfill failure must **propagate**, never degrade to RPC-only: a silent degrade persists an RPC cursor that permanently commits the client to the warm, indexer-skipping path and strands pre-window history.

Spendable balance is recoverable from the latest withdraw/transfer event alone (the event carries `b_tilde`); the receiving balance is a running sum, so every crediting event must be replayed — hence local persistence is load-bearing for correctness, not just speed. `StateEngine.verifyAgainstChain()` re-commits local openings against on-chain points.

## Browser-safety rule for barrels

`src/index.ts` and every `src/*/index.ts` must stay free of `node:*` imports. Node-only modules are excluded from the barrels and reached through `package.json` subpath exports instead:

- `state/json-store.ts` (`node:fs`) → `stellar-confidential-token-sdk/state/json-store`
- `proving/artifacts.ts` (`node:fs`) → `stellar-confidential-token-sdk/proving/artifacts`

In the browser, import circuit JSON through the bundler and pass it to `proverFromArtifact`. `bb.js` resolves its wasm worker via `import.meta.url`, so a bundled copy breaks: serve its `dest/browser/` intact and register it with `setUltraHonkBackendLoader`. The vendored copy must match the pinned `bb.js` version (`0.87.0`), and the page must be cross-origin isolated (`SharedArrayBuffer`).

## Circuit artifacts

`circuits/*.json` (register/withdraw/transfer), `circuits/disclosure/*.json` + pinned `*.vk.json`, and `circuits/vks/*.vk.bin` (the VKs registered with the on-chain verifier; not read by SDK code, shipped for deployment tooling).

Artifacts and code version together — a proof only verifies against a verifier contract whose registered VKs came from these exact circuits. For disclosure, prover and receiver must load *identical* files. All committed artifacts are compiled with nargo `1.0.0-beta.11`, while `@noir-lang/noir_js` is pinned at `1.0.0-beta.9`; the docstring in `proving/artifacts.ts` still says beta.9.

## TypeScript notes

`strict` plus `noUncheckedIndexedAccess` and `verbatimModuleSyntax`: indexed access needs `!`/guards, and type-only imports must use `import type`. ESM throughout — relative imports carry the `.js` extension even from `.ts` sources.
