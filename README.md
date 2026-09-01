# Stellar Confidential Token SDK

TypeScript SDK for confidential tokens on Stellar. It builds circuit
witnesses, generates and verifies UltraHonk zero-knowledge proofs in the
client, submits operations to the Soroban contracts, reconstructs
confidential balances from chain events, and implements two compliance
channels: auditor decryption and off-chain selective disclosure.

The SDK's cryptography is the off-chain mirror of the on-chain Noir circuits —
every generator, domain tag, and derivation matches the circuit library
exactly, validated by executing the real circuits in the test suite.

## Modules (`src/`)

- **crypto** — Grumpkin (`@noble/curves`) and Poseidon2
  (`@zkpassport/poseidon2` raw permutation), with generators, domain tags, and
  derivations matching the Noir circuit library exactly.
- **witness** — per-circuit input builders (register / withdraw / transfer,
  plus the two disclosure circuits), mirroring each circuit's public-input
  order.
- **proving** — UltraHonk via `bb.js` with a **keccak transcript** (required:
  the on-chain verifier uses keccak256 Fiat–Shamir).
- **chain** — RPC client, `{payload, proof}` XDR envelopes, operation
  submitters, and event ingestion, with an optional indexer as a second event
  source.
- **state** — balance reconstruction from chain events with local persistence
  and an on-chain consistency check.
- **auditor** — decrypts the dual auditor ciphertexts emitted by transfers.
- **disclosure** — the off-chain selective-disclosure protocol: witness
  building and proving on the holder side; the full receiver protocol (event
  resolution via RPC, on-chain key lookup, VK pinning, decryption) on the
  receiver side.

## Install

Not yet published to npm. Consume as a git dependency:

```bash
pnpm add "github:brozorec/stellar-confidential-token-sdk"
```

The `prepare` script compiles `dist/` on install.

## Build & test

```bash
pnpm install
pnpm build        # tsc → dist/
pnpm test:fast    # full suite minus proof generation (seconds)
pnpm test         # everything, including real UltraHonk proving (slow)
```

Tests are plain `.mjs` scripts run with `tsx` — run one individually with
`pnpm exec tsx test/<name>.mjs`. `test/indexer-parity.mjs` needs a live
indexer and skips itself unless `CTD_INDEXER_URL` and `CTD_TOKEN` are set.

## Circuit artifacts (`circuits/`)

| Path | Contents |
|:---|:---|
| `circuits/<name>.json` | Compiled ACIR for the register / withdraw / transfer circuits. |
| `circuits/vks/*.vk.bin` | Verification keys, as registered with the on-chain verifier contract. |
| `circuits/disclosure/` | Compiled disclosure circuits and their pinned verification keys. |

Two properties of these files matter to every consumer:

- **They must match the target deployment.** A proof generated against these
  artifacts verifies only on a verifier contract whose registered VKs were
  built from the same circuits. Code and artifacts version together; a release
  states which deployment its artifacts match.
- **The disclosure artifacts are a shared trust anchor.** The proving party
  and the disclosure receiver must load identical files: the receiver derives
  a VK from the circuit bytecode and requires it to match the pinned
  `*.vk.json` byte-for-byte before trusting any verify result.

All proofs use keccak256 Fiat–Shamir transcripts (`bb.js` `{ keccak: true }`)
because the on-chain verifier is keccak. A default-transcript proof never
verifies on-chain.

## Browser usage

`bb.js` spawns its wasm Web Worker through `import.meta.url`-relative paths,
which break once a bundler chunks the library. Serve its `dest/browser/`
directory intact at a stable public path, load it as native ESM at runtime,
and register it with `setUltraHonkBackendLoader`. A vendored copy must track
the version this package pins (`0.87.0`): updating the SDK updates the pin.

The prover also needs `SharedArrayBuffer`, so the embedding page must be
cross-origin isolated (COOP/COEP headers).

## State reconstruction & retention

The protocol's spendable secrets (`v`, `r`) live **only in events** — the
chain stores commitments, not openings. The Soroban RPC `getEvents` API serves
a bounded window of history (about 7 days on testnet), so it alone cannot
reconstruct older state.

The `chain` layer reads events from a hybrid source (`chain/event-source.ts`):
the RPC serves the recent tail, and an optional indexer serves the portion
older than the RPC window. The RPC always owns the tip; the indexer is queried
only for the pre-window backfill.

The `state` layer's `StateEngine` reconstructs `{v, r}` openings from that
source:

- It persists decrypted openings locally and tracks a sync cursor. With the
  RPC alone, local persistence is load-bearing for correctness; with an
  indexer, a fresh client can also rebuild from full history.
- The spendable balance is recoverable from the most recent withdraw or
  transfer event alone, so a regular spender is robust within the window.
- The receiving balance is a running sum: with the RPC only, if an
  incoming-transfer event ages out before you sync, that credit's opening is
  unrecoverable — sync at least once per retention period, or configure an
  indexer.

`StateEngine.verifyAgainstChain()` re-commits the local openings and checks
them against the on-chain commitments, so divergence is detected, never
silently spent.

## License

[MIT](LICENSE)
