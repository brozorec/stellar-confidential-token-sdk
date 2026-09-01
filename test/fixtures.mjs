// SDK.md §6.1 primitive-fixture conformance: "An implementation MUST reproduce
// every output in every file byte-for-byte", and the suite "MUST read those
// files rather than transcribe their values into source".
//
// So this test enumerates test/fixtures/*.json AT RUNTIME (vendored from
// OpenZeppelin/stellar-contracts circuits/lib/testdata; kept in lockstep by
// scripts/check-fixtures-upstream.mjs) and derives its cases from whatever the
// files contain. A fixture added upstream and re-vendored lands here as an
// UNMAPPED failure — never as silence — and a changed vector becomes a hex
// mismatch instead of a quiet cross-client divergence.
//
// Comparison is on the canonical zero-padded 32-byte lowercase hex, not on
// bigints: `0xa` and `0x0a` are the same number and NOT the same fixture
// output. Byte-for-byte is the standard the spec sets, so it is the standard
// applied here — to our outputs AND to the fixture's own formatting.
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { G, H, Grumpkin, scalarMul, commit, ecdh } from "../src/crypto/grumpkin.ts";
import {
  poseidonWithDomain,
  spongeSqueeze2,
  vkFromSk,
  dvkFromVkOp,
  deriveSpendR,
  deriveAllowR,
  deriveTransferBlind,
  encryptAmount,
  encryptBalance,
  encryptAllowance,
  encryptEscDvk,
  encryptAuditorSenderBalance,
} from "../src/crypto/poseidon2.ts";
import { addressToField } from "../src/crypto/address.ts";

const FIXTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

let pass = 0, fail = 0;
const ok = (cond, msg) => { if (cond) { pass++; } else { fail++; console.error("  ✗ " + msg); } };

/**
 * Canonical fixture hex: 0x-prefixed, lowercase, zero-padded to 32 bytes.
 * Deliberately NOT frMod-reducing (unlike field.ts `toHex32`): a non-canonical
 * output must fail loudly, not be silently normalized into a pass.
 */
function hex32(v) {
  if (typeof v !== "bigint" || v < 0n || v >= 1n << 256n) {
    throw new Error(`not a 32-byte value: ${v}`);
  }
  return "0x" + v.toString(16).padStart(64, "0");
}

/** Named generators the fixtures reference, or an explicit {x, y} literal. */
function resolvePoint(p) {
  if (p === "G") return G;
  if (p === "H") return H;
  if (p && typeof p === "object" && "x" in p && "y" in p) {
    return Grumpkin.fromAffine({ x: BigInt(p.x), y: BigInt(p.y) });
  }
  throw new Error(`unknown point spec: ${JSON.stringify(p)}`);
}

const pointOut = (p) => { const a = p.toAffine(); return { x: hex32(a.x), y: hex32(a.y) }; };
const F = BigInt; // fixture input fields are plain hex strings

// One handler per fixture file, keyed by basename. Each takes the vector's
// `inputs` object and returns the computed output in the fixture's own shape
// (hex string, {x, y} of hex strings, or an array of hex strings).
const HANDLERS = {
  address_to_field: (i) => hex32(addressToField(i.strkey)),
  commit: (i) => pointOut(commit(F(i.value), F(i.randomness))),
  derive_allow_r: (i) => hex32(deriveAllowR(F(i.dvk), F(i.sigma_a))),
  derive_spend_r: (i) => hex32(deriveSpendR(F(i.vk), F(i.sigma))),
  derive_transfer_blind: (i) => hex32(deriveTransferBlind(F(i.s), F(i.sigma))),
  dvk_from_vk_op: (i) => hex32(dvkFromVkOp(F(i.vk), F(i.op_i))),
  ecdh: (i) => hex32(ecdh(F(i.scalar), resolvePoint(i.point))),
  encrypt_allowance: (i) => hex32(encryptAllowance(F(i.v_a), F(i.dvk), F(i.sigma_a))),
  encrypt_amount: (i) => hex32(encryptAmount(F(i.v_transfer), F(i.s), F(i.sigma))),
  encrypt_auditor_sender_balance: (i) =>
    hex32(encryptAuditorSenderBalance(F(i.v_new), F(i.s_a_s), F(i.sigma))),
  encrypt_balance: (i) => hex32(encryptBalance(F(i.v_new), F(i.vk), F(i.sigma))),
  encrypt_esc_dvk: (i) => hex32(encryptEscDvk(F(i.dvk), F(i.s), F(i.op_i))),
  poseidon_with_domain: (i) => hex32(poseidonWithDomain(F(i.domain), i.inputs.map(F))),
  pvk_from_vk: (i) => pointOut(scalarMul(F(i.vk), H)),
  scalar_mul: (i) => pointOut(scalarMul(F(i.scalar), resolvePoint(i.point))),
  sponge_squeeze_2: (i) => spongeSqueeze2(F(i.d), F(i.s), F(i.sigma)).map(hex32),
  vk_from_sk: (i) => hex32(vkFromSk(F(i.sk), F(i.wrap))),
};

/**
 * Normalize a fixture's expected output into the same canonical shape a
 * handler returns, WITHOUT round-tripping through bigint: each hex string is
 * only lowercased, so a fixture value that is not itself zero-padded 32-byte
 * hex fails the comparison — that formatting is part of the contract.
 */
function canon(expected) {
  if (typeof expected === "string") return expected.toLowerCase();
  if (Array.isArray(expected)) return expected.map(canon);
  if (expected && typeof expected === "object") {
    return Object.fromEntries(Object.entries(expected).map(([k, v]) => [k, canon(v)]));
  }
  throw new Error(`unrecognized expected-output shape: ${JSON.stringify(expected)}`);
}

const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

const files = readdirSync(FIXTURE_DIR).filter((f) => f.endsWith(".json")).sort();
console.log(`fixtures (§6.1): ${files.length} file(s) in test/fixtures/`);
ok(files.length > 0, "vendored fixtures present (suite would be vacuous without them)");

for (const file of files) {
  const name = file.replace(/\.json$/, "");
  const doc = JSON.parse(readFileSync(join(FIXTURE_DIR, file), "utf8"));

  const handler = HANDLERS[name];
  if (!handler) {
    // A new upstream primitive is a new conformance obligation, not noise.
    ok(false, `${file}: no handler mapped — new upstream fixture? Add one to HANDLERS.`);
    continue;
  }
  ok(doc.primitive === name, `${file}: "primitive" field (${doc.primitive}) matches filename`);
  ok(Array.isArray(doc.vectors) && doc.vectors.length > 0, `${file}: has at least one vector`);

  for (const [idx, vec] of (doc.vectors ?? []).entries()) {
    let actual;
    try {
      actual = handler(vec.inputs);
    } catch (e) {
      ok(false, `${name}[${idx}]: handler threw: ${String(e?.message ?? e)}`);
      continue;
    }
    const expected = canon(vec.output);
    ok(
      eq(actual, expected),
      `${name}[${idx}]: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

// Every mapped handler should have a corresponding vendored file; a fixture
// deleted upstream (and locally re-vendored away) silently removes coverage.
for (const name of Object.keys(HANDLERS)) {
  ok(files.includes(`${name}.json`), `handler ${name} has a vendored fixture file`);
}

console.log(`\nfixtures: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
