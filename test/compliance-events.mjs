// Offline decode test for the compliance/policy membership events
// (frozen/unfrozen + allowlist/blocklist user_*). These all share the
// [symbol, account] / empty-data shape, so buildConfidentialEvent must map each
// to { type, account } using ONLY topic[1] — it must never touch the data
// accessor (the events carry no data fields). Also pins the strict decode of
// the compliance_config() return value. Runs with no infra.

import { buildConfidentialEvent, KNOWN } from "../src/chain/events.ts";

let pass = 0,
  fail = 0;
function check(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.error(`  ✗ ${name}${detail ? `\n      ${detail}` : ""}`);
  }
}

const ACCOUNT = "GBYUUJHG6FE7BTHJYBCSV6YTLLDPVUE5W2LWMTWVDTZ6KOAVNBI6XHIO";
const COMPLIANCE = [
  "frozen",
  "unfrozen",
  "user_allowed",
  "user_disallowed",
  "user_blocked",
  "user_unblocked",
];

// A data accessor that throws on ANY access — proves the decoder never reads
// data for these events (mirrors the empty-Map on-chain shape).
const noData = {
  field: (n) => {
    throw new Error(`unexpected data.field(${n})`);
  },
  point: (n) => {
    throw new Error(`unexpected data.point(${n})`);
  },
  i128: (n) => {
    throw new Error(`unexpected data.i128(${n})`);
  },
  u32: (n) => {
    throw new Error(`unexpected data.u32(${n})`);
  },
};

const base = { ledger: 100, txHash: "deadbeef", cursor: "100-deadbeef-0-0" };
const addr = (i) => (i === 1 ? ACCOUNT : (() => { throw new Error(`unexpected addr(${i})`); })());

for (const sym of COMPLIANCE) {
  check(`${sym}: in KNOWN`, KNOWN.has(sym));
  let ev;
  try {
    ev = buildConfidentialEvent(sym, base, addr, noData);
  } catch (e) {
    check(`${sym}: decodes without touching data`, false, String(e?.message ?? e));
    continue;
  }
  check(`${sym}: type + account`, ev && ev.type === sym && ev.account === ACCOUNT, JSON.stringify(ev));
  check(`${sym}: carries base fields`, ev && ev.ledger === 100 && ev.cursor === base.cursor);
}

// Sanity: an unknown symbol is still rejected.
check("unknown symbol → null", buildConfidentialEvent("definitely_not_an_event", base, addr, noData) === null);

// compliance_config() return value: a contracttype struct writes None as Void,
// so decoding is strict — unlike the event, which omits None fields (replay.mjs).
{
  const { xdr, Keypair } = await import("@stellar/stellar-sdk");
  const POLICY = Keypair.random().publicKey();
  const { decodeComplianceConfig } = await import("../src/chain/events.ts");
  const { complianceConfigVal } = await import("../src/chain/factory.ts");
  const map = (fields) =>
    xdr.ScVal.scvMap(
      Object.keys(fields).sort().map((k) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: fields[k] })),
    );
  const throwsMissing = (val, field) => {
    try {
      decodeComplianceConfig(val);
      return false;
    } catch (e) {
      return new RegExp(`missing.*${field}`).test(e.message);
    }
  };

  const none = decodeComplianceConfig(complianceConfigVal({ policy: null, sacPassthrough: false }));
  check("compliance_config: policy None (Void) → null", none.policy === null && none.sacPassthrough === false);
  const some = decodeComplianceConfig(complianceConfigVal({ policy: POLICY, sacPassthrough: true }));
  check("compliance_config: policy Some → address", some.policy === POLICY && some.sacPassthrough === true);
  check(
    "compliance_config: absent policy throws (rename guard)",
    throwsMissing(map({ sac_passthrough: xdr.ScVal.scvBool(false) }), "policy"),
  );
  check(
    "compliance_config: renamed policy throws",
    throwsMissing(map({ policy_contract: xdr.ScVal.scvVoid(), sac_passthrough: xdr.ScVal.scvBool(false) }), "policy"),
  );
  check(
    "compliance_config: absent sac_passthrough throws",
    throwsMissing(map({ policy: xdr.ScVal.scvVoid() }), "sac_passthrough"),
  );
}

// Indexer (Goldsky JSON) decode of None Option fields: every Void encoding,
// including the `{ type: "void" }` form, reads as None — parity with the RPC
// path, which would otherwise decode the same event correctly.
{
  const { Keypair } = await import("@stellar/stellar-sdk");
  const { parseIndexerEvent } = await import("../src/chain/indexer.ts");
  const DEST = Keypair.random().publicKey();
  const row = (topic, fields) => ({
    id: "100-deadbeef-op-0-event-0",
    ledger: 100,
    txHash: "deadbeef",
    topic,
    value: { map: Object.entries(fields).map(([k, val]) => ({ key: { symbol: k }, val })) },
  });
  const clawback = (destination) =>
    parseIndexerEvent(row([{ symbol: "clawback" }, { address: ACCOUNT }], { amount: { i128: "15" }, destination }));
  const configChanged = (policy) =>
    parseIndexerEvent(row([{ symbol: "compliance_config_changed" }], { policy, sac_passthrough: { bool: false } }));

  const VOIDS = {
    null: null,
    '"void"': "void",
    "{ void }": { void: null },
    '{ type: "void" }': { type: "void" },
    '{ type: "Void", value: null }': { type: "Void", value: null },
  };
  for (const [label, none] of Object.entries(VOIDS)) {
    let claw, cfg, err;
    try {
      claw = clawback(none);
      cfg = configChanged(none);
    } catch (e) {
      err = e;
    }
    check(`indexer clawback destination ${label} → null`, claw?.destination === null && claw.amount === 15n, err?.message);
    check(`indexer compliance_config_changed policy ${label} → null`, cfg?.policy === null, err?.message);
  }
  const some = clawback({ type: "address", value: DEST });
  check("indexer clawback destination { type: \"address\" } → address", some?.destination === DEST);
}

console.log(`\ncompliance-events: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
