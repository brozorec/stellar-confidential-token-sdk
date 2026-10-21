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
const ARITY = { register: 6, withdraw: 16, transfer: 25, clawback: 11 };
for (const [name, n] of Object.entries(ARITY)) {
  const c = JSON.parse(readFileSync(join(CIRCUITS, `${name}.json`), "utf8"));
  const pub = c.abi.parameters.filter((p) => p.visibility === "public");
  ok(pub.length === n, `${name}: ${pub.length} public inputs, expected ${n}`);
  if (name === "withdraw" || name === "transfer") {
    ok(pub.at(-1)?.name === "r_tilde_aud_s", `${name}: last public input is ${pub.at(-1)?.name}, expected r_tilde_aud_s`);
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

console.log(`\nartifacts: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
