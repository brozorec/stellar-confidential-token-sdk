// Verify the vendored §6.1 fixtures (test/fixtures/) are byte-identical to
// OpenZeppelin's packages/confidential/circuits/lib/testdata on `main` (or on
// the ref in $UPSTREAM_REF), and that upstream has grown no fixture we haven't
// vendored.
//
// The fixtures are vendored so `pnpm test:fast` stays hermetic and runs
// offline. The cost of vendoring is that the copy can silently become a fork
// of the specification — the suite would keep passing against a snapshot of
// what the spec used to say. This script closes that gap; CI runs it weekly
// (see .github/workflows/ci.yml) so upstream movement surfaces even when
// nothing in this repository has changed.
//
// Drift is not automatically a bug in either direction: it means the spec
// moved and a human must decide what that implies. Re-vendor with
// `node scripts/vendor-fixtures.mjs <sha>`, review the diff, re-run
// `pnpm exec tsx test/fixtures.mjs`, and update the pin below.
//
// Exit code: 1 on drift, on an upstream file that is gone (HTTP 404), on a
// directory listing that is gone (HTTP 404 — the path moved, as it did when the
// crate split out of packages/tokens), or on a new upstream fixture we don't
// vendor. Plain network failures (offline, 5xx, API rate limit) only warn and
// exit 0 — an offline run must not false-alarm, and the weekly networked CI run
// is the one that carries the conformance claim. Set GITHUB_TOKEN to lift the
// API rate limit.
//
// The comparison target is `main`, not the pin, on purpose: comparing against
// the vendored commit would only re-prove the copy, never detect that the spec
// moved. CI runs this as its own job, so drift reports without blocking tests.
//
// Vendored from OpenZeppelin/stellar-contracts commit:
//   ddc327eb92d63709436da3a8455f641c2d5476c5  (v0.8.0, 2026-10-20)

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "test", "fixtures");

const UPSTREAM_PATH = "packages/confidential/circuits/lib/testdata";
const REF = process.env.UPSTREAM_REF || "main";
const RAW = `https://raw.githubusercontent.com/OpenZeppelin/stellar-contracts/${REF}/${UPSTREAM_PATH}`;
const API = `https://api.github.com/repos/OpenZeppelin/stellar-contracts/contents/${UPSTREAM_PATH}?ref=${REF}`;
const API_HEADERS = { accept: "application/vnd.github+json" };
if (process.env.GITHUB_TOKEN) API_HEADERS.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

const sha = (buf) => createHash("sha256").update(buf).digest("hex").slice(0, 16);

// README.md is vendored alongside for documentation and checked the same way.
const files = readdirSync(FIXTURES)
  .filter((f) => f.endsWith(".json") || f === "README.md")
  .sort();
if (files.length === 0) {
  console.error("No vendored fixtures found in test/fixtures/ — the check is vacuous.");
  process.exit(1);
}

let drifted = 0;
let missing = 0;
let unreachable = 0;

for (const file of files) {
  const local = readFileSync(join(FIXTURES, file));

  let resp;
  try {
    resp = await fetch(`${RAW}/${file}`);
  } catch (e) {
    console.warn(`?  ${file.padEnd(38)} unreachable: ${e?.message ?? e}`);
    unreachable++;
    continue;
  }
  if (resp.status === 404) {
    // Renamed or deleted upstream: the spec moved out from under the pin.
    console.error(`!! ${file.padEnd(38)} GONE upstream (404)`);
    missing++;
    continue;
  }
  if (!resp.ok) {
    console.warn(`?  ${file.padEnd(38)} upstream returned ${resp.status}`);
    unreachable++;
    continue;
  }

  const remote = Buffer.from(await resp.arrayBuffer());
  if (local.equals(remote)) {
    console.log(`ok ${file.padEnd(38)} ${sha(local)}`);
  } else {
    console.error(`!! ${file.padEnd(38)} DRIFTED  local ${sha(local)} vs upstream ${sha(remote)}`);
    drifted++;
  }
}

// New upstream fixtures are new conformance obligations (§6.1 covers "every
// file"), so an unvendored one is a failure, not a curiosity.
try {
  const resp = await fetch(API, { headers: API_HEADERS });
  if (resp.status === 404) {
    // The whole directory is gone: the per-file checks above 404'd too, but
    // say so once, plainly — the fixtures moved, they did not each vanish.
    console.error(`!! upstream fixture directory GONE (404): ${UPSTREAM_PATH}@${REF}`);
    missing++;
  } else if (resp.ok) {
    const listing = await resp.json();
    const upstreamNames = listing
      .map((e) => e.name)
      .filter((n) => n.endsWith(".json"))
      .sort();
    for (const name of upstreamNames) {
      if (!files.includes(name)) {
        console.error(`!! ${name.padEnd(38)} NEW upstream fixture, not vendored`);
        missing++;
      }
    }
  } else {
    console.warn(`?  upstream directory listing returned ${resp.status}; new-file check skipped`);
    unreachable++;
  }
} catch (e) {
  console.warn(`?  upstream directory listing unreachable: ${e?.message ?? e}`);
  unreachable++;
}

if (unreachable > 0) {
  console.warn(
    `\n${unreachable} check(s) skipped for network reasons — fine offline; ` +
      "the weekly CI run is the authoritative one.",
  );
}

if (drifted + missing > 0) {
  console.error(
    `\n${drifted + missing} fixture(s) out of sync with upstream.\n` +
      "This is not automatically a bug: the specification moved, and someone must\n" +
      "decide what that means here. Re-vendor (scripts/vendor-fixtures.mjs), review\n" +
      "the diff, run `pnpm exec tsx test/fixtures.mjs`, and update the pinned SHA\n" +
      "in both scripts — never silence the mismatch.",
  );
}

process.exit(drifted + missing > 0 ? 1 : 0);
