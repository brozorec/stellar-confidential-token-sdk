// One-shot vendoring helper: fetch the upstream testdata fixtures at a pinned
// commit into test/fixtures/. Kept for re-vendoring when the drift check
// (scripts/check-fixtures-upstream.mjs) reports upstream moved; review the
// diff, then update PINNED_SHA there and here.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const SHA = process.argv[2] ?? "fbfde388e1b72afa93d6b1c922067879b20e81db";
const BASE =
  `https://raw.githubusercontent.com/OpenZeppelin/stellar-contracts/${SHA}` +
  "/packages/tokens/src/confidential/circuits/lib/testdata";

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
  "encrypt_auditor_sender_balance.json",
  "encrypt_balance.json",
  "encrypt_esc_dvk.json",
  "poseidon_with_domain.json",
  "pvk_from_vk.json",
  "scalar_mul.json",
  "sponge_squeeze_2.json",
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
