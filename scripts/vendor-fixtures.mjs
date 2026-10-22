// One-shot vendoring helper: fetch the upstream testdata fixtures at a pinned
// commit into test/fixtures/. Kept for re-vendoring when the drift check
// (scripts/check-fixtures-upstream.mjs) reports upstream moved; review the
// diff, then update the pinned SHA there and here.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// stellar-contracts v0.8.0 (stellar-confidential 0.8.0).
const SHA = process.argv[2] ?? "ddc327eb92d63709436da3a8455f641c2d5476c5";
const BASE =
  `https://raw.githubusercontent.com/OpenZeppelin/stellar-contracts/${SHA}` +
  "/packages/confidential/circuits/lib/testdata";

const FILES = [
  "address_to_field.json",
  "commit.json",
  "derive_allow_r.json",
  "derive_spend_r.json",
  "derive_transfer_blind.json",
  "dvk_from_vk_op.json",
  "ecdh.json",
  "encrypt_allowance.json",
  "encrypt_amount.json",
  "encrypt_balance.json",
  "encrypt_esc_allow_r_auditor.json",
  "encrypt_esc_dvk.json",
  "poseidon_with_domain.json",
  "pvk_from_vk.json",
  "scalar_mul.json",
  "sponge_squeeze_2.json",
  "sponge_squeeze_3.json",
  "vk_from_sk.json",
  "README.md",
];

const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "test", "fixtures");
mkdirSync(dir, { recursive: true });

let failed = 0;
for (const f of FILES) {
  const r = await fetch(`${BASE}/${f}`);
  if (!r.ok) {
    console.error(`FAILED ${f}: HTTP ${r.status}`);
    failed++;
    continue;
  }
  writeFileSync(join(dir, f), Buffer.from(await r.arrayBuffer()));
  console.log(`ok ${f}`);
}
process.exit(failed === 0 ? 0 : 1);
