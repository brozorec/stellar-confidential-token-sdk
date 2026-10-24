// Circuit-artifact provenance (no proving): every upstream-sourced file under
// circuits/ must match the sha256 recorded in circuits/manifest.json, and no
// unrecorded file may sit beside them. A proof only verifies against a verifier
// whose registered VKs came from these exact circuits, so an artifact swapped
// without updating the record — or a VK bin left over from an older release —
// is a silent on-chain incompatibility. Also pins each circuit's public-input
// arity, the count the contract's PI blob must match.
import { readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { VERSIONS, versionMatrix } from "../src/version.ts";
import { addressToField } from "../src/crypto/address.ts";
import { toHex32 } from "../src/crypto/field.ts";

const CIRCUITS = join(dirname(fileURLToPath(import.meta.url)), "..", "circuits");

let pass = 0, fail = 0;
const ok = (cond, msg) => { if (cond) { pass++; } else { fail++; console.error("  ✗ " + msg); } };

const manifest = JSON.parse(readFileSync(join(CIRCUITS, "manifest.json"), "utf8"));
const sha = (p) => createHash("sha256").update(readFileSync(join(CIRCUITS, p))).digest("hex");

for (const [file, expected] of Object.entries(manifest.sha256)) {
  let actual;
  try {
    actual = sha(file);
  } catch {
    ok(false, `${file}: listed in manifest but missing`);
    continue;
  }
  ok(actual === expected, `${file}: sha256 ${actual} != manifest ${expected}`);
}

// Everything outside disclosure/ must be recorded (disclosure is not upstream).
const present = [
  ...readdirSync(CIRCUITS).filter((f) => f.endsWith(".json") && f !== "manifest.json"),
  ...readdirSync(join(CIRCUITS, "vks")).map((f) => `vks/${f}`),
];
for (const f of present) ok(f in manifest.sha256, `${f}: present but not recorded in manifest.json`);

// Public-input arity per circuit (withdraw/transfer grew r_tilde_aud_s in v0.8.0).
const ARITY = { register: 6, withdraw: 16, transfer: 25, set_spender: 26, spender_transfer: 25, clawback: 11 };
for (const [name, n] of Object.entries(ARITY)) {
  const c = JSON.parse(readFileSync(join(CIRCUITS, `${name}.json`), "utf8"));
  const pub = c.abi.parameters.filter((p) => p.visibility === "public");
  ok(pub.length === n, `${name}: ${pub.length} public inputs, expected ${n}`);
  if (name === "withdraw" || name === "transfer" || name === "spender_transfer") {
    ok(pub.at(-1)?.name === "r_tilde_aud_s", `${name}: last public input is ${pub.at(-1)?.name}, expected r_tilde_aud_s`);
  }
  if (name === "set_spender") {
    ok(pub.at(-1)?.name === "r_a_tilde_aud_s", `${name}: last public input is ${pub.at(-1)?.name}, expected r_a_tilde_aud_s`);
  }
  ok(
    c.noir_version.startsWith(manifest.toolchain.nargo + "+"),
    `${name}: compiled by ${c.noir_version}, manifest says ${manifest.toolchain.nargo}`,
  );
  ok(
    Object.values(c.file_map).every((f) => !f.path.startsWith("/")),
    `${name}: file_map carries an absolute (machine-specific) path`,
  );
}
// The on-chain verifier's VK layout: 32-byte header + 27 × 64-byte points.
for (const f of present.filter((p) => p.endsWith(".vk.bin"))) {
  ok(readFileSync(join(CIRCUITS, f)).length === 1760, `${f}: not 1760 bytes`);
}

// Disclosure: built here (scripts/build-disclosure.mjs), recorded separately.
// Prover and receiver must load identical files, so these hashes are the
// cross-client contract for the disclosure layer.
const disclosure = manifest.disclosure?.sha256 ?? {};
const disclosurePresent = readdirSync(join(CIRCUITS, "disclosure"))
  .filter((f) => f.endsWith(".json"))
  .map((f) => `disclosure/${f}`);
ok(disclosurePresent.length === 4, `disclosure/: ${disclosurePresent.length} json files, expected 4`);
for (const f of disclosurePresent) {
  ok(f in disclosure, `${f}: present but not recorded in manifest.json disclosure`);
  if (f in disclosure) ok(sha(f) === disclosure[f], `${f}: sha256 ${sha(f)} != manifest ${disclosure[f]}`);
}
const DISCLOSURE_ARITY = { disclose_recipient: 13, disclose_sender: 15 };
for (const [name, n] of Object.entries(DISCLOSURE_ARITY)) {
  const c = JSON.parse(readFileSync(join(CIRCUITS, "disclosure", `${name}.json`), "utf8"));
  const vk = JSON.parse(readFileSync(join(CIRCUITS, "disclosure", `${name}.vk.json`), "utf8"));
  const pub = c.abi.parameters.filter((p) => p.visibility === "public");
  ok(pub.length === n, `${name}: ${pub.length} public inputs, expected ${n}`);
  ok(
    c.noir_version.startsWith(manifest.toolchain.nargo + "+") && vk.noirVersion === c.noir_version,
    `${name}: artifact ${c.noir_version} / VK ${vk.noirVersion}, manifest says ${manifest.toolchain.nargo}`,
  );
  ok(vk.oracleHash === "keccak" && vk.zk === true, `${name}: VK pin is not keccak + ZK`);
  ok(
    Object.values(c.file_map).every((f) => !f.path.startsWith("/")),
    `${name}: file_map carries an absolute (machine-specific) path`,
  );
  // The disclosure circuits must be built on the same circuit library release
  // as the core circuits (the point_hint fix lives there).
  const toml = readFileSync(join(CIRCUITS, "disclosure", "noir", name, "Nargo.toml"), "utf8");
  ok(toml.includes(`tag = "${manifest.source.tag}"`), `${name}: Nargo.toml does not pin ${manifest.source.tag}`);
}

// The exported version matrix must describe what actually ships.
const pkg = JSON.parse(readFileSync(join(CIRCUITS, "..", "package.json"), "utf8"));
ok(VERSIONS.sdk === pkg.version, `VERSIONS.sdk ${VERSIONS.sdk} != package.json ${pkg.version}`);
ok(
  `${VERSIONS.protocol.crate} ${VERSIONS.protocol.version}` === manifest.source.crate &&
    VERSIONS.protocol.tag === manifest.source.tag &&
    VERSIONS.protocol.commit === manifest.source.commit &&
    VERSIONS.protocol.repository === manifest.source.repository,
  "VERSIONS.protocol does not match manifest.json source",
);
ok(
  VERSIONS.toolchain.nargo === manifest.toolchain.nargo && VERSIONS.toolchain.bb === manifest.toolchain.bb,
  "VERSIONS.toolchain nargo/bb do not match manifest.json toolchain",
);
ok(VERSIONS.toolchain.bbJs === pkg.dependencies["@aztec/bb.js"], "VERSIONS.toolchain.bbJs != package.json");
ok(VERSIONS.toolchain.noirJs === pkg.dependencies["@noir-lang/noir_js"], "VERSIONS.toolchain.noirJs != package.json");
const vkEntries = Object.entries({ ...manifest.sha256, ...(manifest.disclosure?.sha256 ?? {}) })
  .filter(([f]) => f.endsWith(".vk.bin") || f.endsWith(".vk.json"))
  .sort(([a], [b]) => a.localeCompare(b));
ok(
  JSON.stringify(vkEntries) ===
    JSON.stringify(Object.entries(VERSIONS.verificationKeys).sort(([a], [b]) => a.localeCompare(b))),
  "VERSIONS.verificationKeys != the VK entries of manifest.json",
);
const TOKEN = "CBF64DEOVQAXJFBSNGFEUT2AH4H7K5JBY3ZYJ5GVEINMNSDISWRG5N3F";
ok(versionMatrix(TOKEN).deployment?.addrF === toHex32(addressToField(TOKEN)), "versionMatrix addr_f");
ok(versionMatrix().deployment === null, "versionMatrix without a token has no deployment");

console.log(`\nartifacts: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
