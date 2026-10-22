// Rebuild the selective-disclosure circuits and re-pin what the SDK ships:
//
//   circuits/disclosure/<name>.json     nargo artifact, file_map paths made
//                                       machine-independent
//   circuits/disclosure/<name>.vk.json  UltraHonk VK (keccak transcript, ZK
//                                       flavour), base64
//   circuits/manifest.json `disclosure` sha256 of all four files
//   src/version.ts                      the two disclosure VK sha256s in
//                                       VERSIONS.verificationKeys
//
//   pnpm exec tsx scripts/build-disclosure.mjs [--check]
//
// --check rebuilds and compares against the committed files instead of
// writing them (CI), so the shipped artifacts provably come from the source.
//
// The Noir source is this repository's own (circuits/disclosure/noir/):
// upstream specifies the disclosure circuits but ships no implementation. It
// depends on upstream's circuit library at the tag recorded in each
// Nargo.toml, which must match circuits/manifest.json `source.tag`.
//
// Requires nargo at circuits/manifest.json `toolchain.nargo` on PATH (its
// noir-inspector runs the lookup check at the end) and the bb.js CRS, same as
// test/prove.mjs. Prover and
// receiver must load identical files, so any change here is a compatibility
// break between clients: re-run test/disclosure.mjs afterwards.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { CircuitProver } from "../src/proving/prover.ts";

const CIRCUITS = ["disclose_recipient", "disclose_sender"];
const CHECK = process.argv.includes("--check");

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(root, "circuits", "disclosure");
const noirDir = join(outDir, "noir");
const manifestPath = join(root, "circuits", "manifest.json");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const NARGO = manifest.toolchain.nargo;

// Nothing is written until every check below has passed (the lookup check
// included), so a failed rebuild leaves the tree as it was.
//
// The version matrix restates the disclosure VK hashes (test/artifacts.mjs
// pins it against the manifest), so it moves with every rebuild.
const versionPath = join(root, "src", "version.ts");
const versionSrc = readFileSync(versionPath, "utf8");
const vkEntry = (key) => new RegExp(`("${key.replaceAll(".", "\\.")}": )"[0-9a-f]{64}"`);
for (const name of CIRCUITS) {
  const key = `disclosure/${name}.vk.json`;
  if (!vkEntry(key).test(versionSrc)) {
    console.error(`src/version.ts has no VERSIONS.verificationKeys entry for ${key}`);
    process.exit(1);
  }
}

const nargoVersion = execFileSync("nargo", ["--version"], { encoding: "utf8" });
if (!nargoVersion.includes(`nargo version = ${NARGO}`)) {
  console.error(`expected nargo ${NARGO}, found:\n${nargoVersion}`);
  process.exit(1);
}
for (const name of CIRCUITS) {
  const toml = readFileSync(join(noirDir, name, "Nargo.toml"), "utf8");
  if (!toml.includes(`tag = "${manifest.source.tag}"`)) {
    console.error(`${name}/Nargo.toml does not pin the library at ${manifest.source.tag}`);
    process.exit(1);
  }
}

console.log(`==> nargo compile --workspace (${noirDir})`);
execFileSync("nargo", ["compile", "--workspace"], { cwd: noirDir, stdio: "inherit" });

// file_map is debug-only, but nargo records absolute paths in it. Keep them
// repo-relative for our sources and upstream-relative for the git dependency
// (nargo's checkout is ~/nargo/github.com/<org>/<repo>/<tag>/...), matching
// the core artifacts.
const relativePath = (p) =>
  p.startsWith(root + "/")
    ? p.slice(root.length + 1)
    : p.replace(/^.*\/nargo\/github\.com\/[^/]+\/[^/]+\/[^/]+\//, "");

const sha256 = {};
/** Write mode: `[path, label, text]`, flushed once every check has passed. */
const pending = [];
let stale = 0;
const emit = (file, text) => {
  sha256[`disclosure/${file}`] = createHash("sha256").update(text).digest("hex");
  const path = join(outDir, file);
  if (!CHECK) return pending.push([path, `disclosure/${file}`, text]);
  let committed = null;
  try {
    committed = readFileSync(path, "utf8");
  } catch {}
  if (committed !== text) {
    console.error(`    STALE disclosure/${file}: does not match a rebuild from source`);
    stale++;
  }
};

for (const name of CIRCUITS) {
  const artifact = JSON.parse(readFileSync(join(noirDir, "target", `${name}.json`), "utf8"));
  for (const f of Object.values(artifact.file_map)) f.path = relativePath(f.path);
  const leftover = Object.values(artifact.file_map).filter((f) => f.path.startsWith("/"));
  if (leftover.length) {
    console.error(`${name}: unrecognised absolute file_map paths: ${leftover.map((f) => f.path)}`);
    process.exit(1);
  }
  emit(`${name}.json`, JSON.stringify(artifact));

  const prover = new CircuitProver(artifact, { zk: true });
  const vk = await prover.verificationKey();
  await prover.destroy();
  emit(
    `${name}.vk.json`,
    JSON.stringify(
      {
        circuitId: name,
        scheme: "ultra_honk",
        oracleHash: "keccak",
        zk: true,
        noirVersion: artifact.noir_version,
        vkBase64: Buffer.from(vk).toString("base64"),
      },
      null,
      2,
    ) + "\n",
  );
  console.log(`    rebuilt disclosure/${name}.json + .vk.json (${vk.length}B VK)`);
}

const disclosure = {
  source: "circuits/disclosure/noir (this repository); circuit library from `source` above",
  proof: "UltraHonk, keccak transcript, ZK flavour (verified off-chain by bb.js)",
  sha256,
};
if (CHECK) {
  if (JSON.stringify(manifest.disclosure) !== JSON.stringify(disclosure)) {
    console.error("    STALE circuits/manifest.json `disclosure`");
    stale++;
  }
} else {
  manifest.disclosure = disclosure;
  pending.push([manifestPath, "circuits/manifest.json", JSON.stringify(manifest, null, 2) + "\n"]);
}

let versionNext = versionSrc;
for (const name of CIRCUITS) {
  const key = `disclosure/${name}.vk.json`;
  versionNext = versionNext.replace(vkEntry(key), `$1"${sha256[key]}"`);
}
if (versionNext !== versionSrc) {
  if (CHECK) {
    console.error("    STALE src/version.ts VERSIONS.verificationKeys");
    stale++;
  } else {
    pending.push([versionPath, "src/version.ts", versionNext]);
  }
}

console.log("==> scripts/check-witness-lookups.sh");
execFileSync(
  join(root, "scripts", "check-witness-lookups.sh"),
  CIRCUITS.map((n) => join(noirDir, "target", `${n}.json`)),
  { stdio: "inherit" },
);

for (const [path, label, text] of pending) {
  writeFileSync(path, text);
  console.log(`    wrote ${label}`);
}

if (stale) {
  console.error(`${stale} committed file(s) differ from a rebuild; run without --check and commit.`);
  process.exit(1);
}
