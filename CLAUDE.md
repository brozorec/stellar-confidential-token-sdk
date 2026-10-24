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
pnpm exec tsx scripts/build-disclosure.mjs [--check]   # rebuild/verify disclosure artifacts (nargo 1.0.0-beta.11)
scripts/check-witness-lookups.sh                       # no witness-dependent lookups in any shipped circuit
(cd circuits/disclosure/noir && nargo test --workspace)
```

There is no linter and no test framework. Tests are plain `.mjs` scripts run under `tsx`; each keeps its own `pass`/`fail` counters and ends with `process.exit(fail === 0 ? 0 : 1)`. They import **`../src/*.ts` directly**, so `pnpm build` is not a prerequisite for running them.

`pnpm test` / `pnpm test:fast` are hand-maintained `&&` chains in `package.json` — a new test file runs in CI only once it is added to those chains.

Env-gated tests (`indexer-parity.mjs`, `shape-filter.mjs`) skip cleanly with exit 0 unless `CTD_INDEXER_URL` and `CTD_TOKEN` are set; `CTD_RPC_URL` and `CTD_FROM_LEDGER` are optional overrides. `onchain-e2e.mjs` (in `pnpm test` only) skips unless `CTD_E2E_RPC_URL` and `CTD_E2E_WASM_DIR` are set; it deploys the upstream `examples/confidential` wasms to a friendbot network (its header has the quickstart recipe) and is the only test where the Rust verifier judges SDK proofs. CI (`.github/workflows/ci.yml`) runs `test:fast` on every PR, the two proving tests on main pushes only, and as their own jobs the upstream fixture drift check and `disclosure-circuits` (Noir tests, `build-disclosure.mjs --check`, lookup check).

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
  decode), `indexer.ts` (Goldsky JSON decode), `event-source.ts` (hybrid), plus `factory.ts`, `admin.ts` (targeting the upstream `examples/confidential/{factory,compliant-token,allowlist-policy}`: `u32` deploy salts, access-control roles), `errors.ts` for the dashboard/admin personas.
- **`state/`** — `StateEngine` replays events into `{v, r}` openings behind a pluggable `StateStore`. `SpenderWallet` (`spender.ts`) is the spender role: it reads a delegation's allowance from the on-chain entry, with no replay and no persistence.
- **`auditor/`** — decrypts the auditor channels from a raw event + the auditor secret `k`. No holder cooperation needed.
- **`disclosure/`** — off-chain selective disclosure: holder proves, receiver
  verifies through a mandatory multi-step protocol.

## Invariants that must not drift

**Keccak transcript is mandatory.** Every proof is generated and verified with a keccak transcript because the on-chain verifier uses keccak256 Fiat–Shamir; a default-transcript proof verifies locally and fails on-chain. On-chain circuits use the non-ZK flavour (`KECCAK` in `proving/prover.ts`), the only one the verifier implements. The disclosure circuits use the ZK flavour (`KECCAK_ZK`, `new CircuitProver(artifact, { zk: true })`): their proofs go to a third party and are verified by bb.js. The VK bytes are identical across flavours, so nothing but `prover.zk` checks in `disclosure/` catches a mix-up — a wrong-flavour proof just fails to verify.

**Domain tags are the wire format.** `DOMAIN` in `crypto/constants.ts` is exactly `1n..17n`, distinct, one sponge mode each (11 is squeezed three-wide, 12 two-wide). Tags 1–13 and 17 are absorbed on-chain or in-circuit; 14–16 are absorbed nowhere, so drift there breaks *cross-client* reads silently — nothing fails. `test/smoke.mjs` pins all seventeen; treat that test as the spec.

**`fpAdd` vs `frAdd`.** Blinding factors accumulate mod `p` (the Grumpkin group order, `FP_MODULUS`), values mod `r` (`FR_MODULUS`). Using `frAdd` on a blinding sum diverges by `p - r` about half the time and only surfaces as an on-chain commitment mismatch after a merge.

**Public-input order.** Each witness builder's docstring records the circuit's public-input order; `chain/payload.ts` encodes structs as `ScMap` with symbol keys **sorted ascending**, and a `Point` is a flat `BytesN<64>` (`be(x)||be(y)`, identity = 64 zero bytes) — never an `{x, y}` sub-map.

**Delegation keys.** `escrowed_dvk` is two field limbs `(R_x, dvk_cipher)`, not a point. `R.y` is not stored and `ecdh` absorbs `S.y`, so `recoverEscrowedDvk` (`crypto/delegation.ts`) tries both roots and accepts only a `dvk` whose allowance opening re-commits to `C_a`. A spender transfer keys every pad, and its `r_e`, by the replacement salt `σ_a'` and the SPENDER's `vk`. The stored `σ_a` only opens the current allowance. D-sender on a SpenderTransfer depends on exactly that derivation. The sender-auditor channel of both delegation circuits is the OWNER's `auditor_id`.

**Contract field names appear verbatim** in `chain/events.ts` (`buildConfidentialEvent`) and `chain/client.ts` (`parseAccount`, `parseDelegation`). Both have deliberate completeness checks that turn a contract-side rename into a loud throw; keep them.

**One event shape, two decoders.** `buildConfidentialEvent` is the single shape definition; the RPC (XDR) and indexer (Goldsky JSON) paths only supply different `addr`/`EventDataAccessor` adapters. `test/indexer-parity.mjs` pins that the two decode byte-identically.

**Disclosure trust boundary** (`disclosure/verify.ts`): the only values taken from a bundle are `(R_disc, v_tilde_disc)` plus the event *reference*. Event fields, PVKs, and `addr_f` are re-resolved from chain state; `(P_R, nu)` come from the verifier's own request record. Widening what the bundle contributes voids the proof's meaning. The VK derived from the loaded circuit bytecode is also compared byte-for-byte against the pinned `circuits/disclosure/*.vk.json` (`pinnedVk` is mandatory). D-sender re-derives `r_e` from `(vk, sigma)` and reports an event it does not reproduce as `{ disclosable: false }` (`NotDisclosableError` from the builder), never as a proving error.

## Event retention — the design's central constraint

Spendable secrets (`v`, `r`) live only in events; the chain stores commitments. Soroban RPC `getEvents` retains ~7 days.

`chain/event-source.ts` splits: the optional Goldsky indexer serves `[next, seam-1]`, the RPC serves `[seam, head]`, where `seam = rpcOldest + RPC_SEAM_MARGIN`. The ranges are disjoint by construction; `dedupeById` is a boundary guard, and its **stable sort by ledger only** is load-bearing because `StateEngine.apply` is order-sensitive and not idempotent.

A *configured* indexer's backfill failure must **propagate**, never degrade to RPC-only: a silent degrade persists an RPC cursor that permanently commits the client to the warm, indexer-skipping path and strands pre-window history.

Spendable balance restarts from the latest checkpoint (withdraw, outgoing transfer, or `set_spender` — the events carrying `b_tilde`), but merge, `revoke_spender` and `clawback` after it are folds, and the receiving balance is a running sum — so every one of those events must be replayed in order, hence local persistence is load-bearing for correctness, not just speed. `StateEngine.sync()` ends by re-committing the local openings against the on-chain points and throws `StateDivergedError` only on a mismatch with a balance read at the ledger the events were fetched through (`ChainClient.confidentialBalanceAt` returns the read's ledger). A mismatching read ahead of it re-syncs incrementally, one behind it re-reads, capped; if it never lines up the error is `StateUnverifiedError`, which never claims a missed event. `spendableForProof()` repeats the check once before proving.

The one exception is the spender's allowance. The delegation entry stores `a_tilde`, `allowance_salt` and `escrowed_dvk`, so `SpenderWallet` re-reads it from storage before every proof. Expiry is surfaced as a status and never hidden: an expired, unrevoked entry still holds value, and only `allowanceForProof()` refuses it. "Expired" means `readLedger >= live_until_ledger`.

## Browser-safety rule for barrels

`src/index.ts` and every `src/*/index.ts` must stay free of `node:*` imports. Node-only modules are excluded from the barrels and reached through `package.json` subpath exports instead:

- `state/json-store.ts` (`node:fs`) → `stellar-confidential-token-sdk/state/json-store`
- `proving/artifacts.ts` (`node:fs`) → `stellar-confidential-token-sdk/proving/artifacts`

In the browser, import circuit JSON through the bundler and pass it to `proverFromArtifact`. `bb.js` resolves its wasm worker via `import.meta.url`, so a bundled copy breaks: serve its `dest/browser/` intact and register it with `setUltraHonkBackendLoader`. The vendored copy must match the pinned `bb.js` version (`0.87.0`), and the page must be cross-origin isolated (`SharedArrayBuffer`).

## Circuit artifacts

`circuits/*.json` (register/withdraw/transfer/set_spender/spender_transfer/clawback: `nargo compile --package circuit_<name>` of stellar-contracts `v0.8.0` with the absolute `file_map` prefix stripped to `packages/confidential/…`), `circuits/disclosure/*.json` + pinned `*.vk.json` (built here from `circuits/disclosure/noir/`, which depends on upstream's circuit library by git tag — upstream ships only the disclosure spec), and `circuits/vks/*.vk.bin` (the VKs registered with the on-chain verifier; not read by SDK code, shipped for deployment tooling). `circuits/manifest.json` records the upstream tag/commit, toolchain and a sha256 per upstream file; `test/artifacts.mjs` fails on any unrecorded or changed file, and `test/prove.mjs` checks each bb.js-derived VK equals its `.vk.bin`.

Artifacts and code version together — a proof only verifies against a verifier contract whose registered VKs came from these exact circuits. For disclosure, prover and receiver must load *identical* files: after editing `circuits/disclosure/noir/` run `pnpm exec tsx scripts/build-disclosure.mjs` (rewrites the artifacts, VK pins, `manifest.json` `disclosure` and the disclosure VK hashes in `src/version.ts`), and CI's `--check` run fails on any drift. Every circuit must pass `scripts/check-witness-lookups.sh`: without ZK, a `multi_scalar_mul` over the constant `G`/`H` lowers to bb's fixed-base lookup tables and the proof commits which rows the secret scalars hit — the library's `scalar_mul`/`commit` pass the generators as witnesses for this reason, so never call `multi_scalar_mul` on them directly. All committed artifacts are compiled with nargo `1.0.0-beta.11`, matching `@noir-lang/noir_js` `1.0.0-beta.11`; `@aztec/bb.js` stays at exactly `0.87.0` (the on-chain verifier is audited against it).

`src/version.ts` (`VERSIONS`, `versionMatrix`) is the spec's version matrix; `test/artifacts.mjs` pins it against `manifest.json` and `package.json`, so a re-vendor, dependency bump, or release must update it. The README's Coverage section is the spec-required declaration of partial role/circuit coverage — change it whenever a role, circuit, or disclosure variant is added.

## TypeScript notes

`strict` plus `noUncheckedIndexedAccess` and `verbatimModuleSyntax`: indexed access needs `!`/guards, and type-only imports must use `import type`. ESM throughout — relative imports carry the `.js` extension even from `.ts` sources.
