// Offline replay test (no proving, no network) for every balance-changing
// event, through the REAL RPC decoder (XDR) and StateEngine.sync().
//
// The expected on-chain commitments are computed the way the CONTRACT moves
// them — point arithmetic (C_spend += C_a on revoke; C_spend + C_receive −
// amount·G on clawback; checkpoints overwrite) — not with the engine's opening
// math, so a wrong replay rule surfaces as a StateDivergedError from the
// consistency check that every sync now ends with. Covers soroban-sdk 28's
// omission of None Option fields (clawback.destination, policy).
import { xdr, Address, Keypair, nativeToScVal } from "@stellar/stellar-sdk";

import { deriveKeys } from "../src/crypto/keys.ts";
import { G, H, IDENTITY, commit, scalarMul, pointToBytes } from "../src/crypto/grumpkin.ts";
import { randomScalar, toBytes32BE } from "../src/crypto/field.ts";
import { addressToField } from "../src/crypto/address.ts";
import { recoverEscrowedDvk } from "../src/crypto/delegation.ts";
import { buildTransferWitness } from "../src/witness/transfer.ts";
import { buildSetSpenderWitness } from "../src/witness/set-spender.ts";
import { buildSpenderTransferWitness } from "../src/witness/spender-transfer.ts";
import { StateEngine, StateDivergedError, StateUnverifiedError } from "../src/state/engine.ts";
import { MemoryStore } from "../src/state/store.ts";

let pass = 0, fail = 0;
function check(name, cond, detail) {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.error(`  ✗ ${name}${detail ? `\n      ${detail}` : ""}`); }
}

const TOKEN = "CCREDIB3DG3IBVUKBL7QMEK4MTPSTODR7MQ34QY4SQ5LZ5L4WFWNVNXG";
const addrF = addressToField(TOKEN);
const me = deriveKeys(randomScalar(), addrF);
const A = Keypair.random().publicKey();     // me
const X = Keypair.random().publicKey();     // some other owner / depositor
const C = Keypair.random().publicKey();     // a third party
const S = Keypair.random().publicKey();     // my spender
const bob = deriveKeys(randomScalar(), addrF);
const B = Keypair.random().publicKey();

// --- XDR event builders (the shape `getEvents` returns) ----------------------
const sym = (s) => xdr.ScVal.scvSymbol(s);
const adr = (a) => new Address(a).toScVal();
const fld = (v) => xdr.ScVal.scvBytes(Buffer.from(toBytes32BE(v)));
const pnt = (p) => xdr.ScVal.scvBytes(Buffer.from(pointToBytes(p)));
const i128 = (v) => nativeToScVal(v, { type: "i128" });
const data = (fields) =>
  xdr.ScVal.scvMap(
    Object.keys(fields).sort().map((k) => new xdr.ScMapEntry({ key: sym(k), val: fields[k] })),
  );

let seq = 0;
const ev = (name, topics, fields) => {
  seq++;
  const ledger = 10 + seq;
  return {
    id: `${(BigInt(ledger) << 32n).toString()}-${seq}`,
    ledger,
    txHash: `tx${seq}`,
    topic: [sym(name), ...topics.map(adr)],
    value: data(fields),
  };
};

// --- The scenario, with the contract-side commitments tracked alongside -------
let cSpend = IDENTITY, cRecv = IDENTITY;
const events = [];

events.push(ev("register", [A], { auditor_id: xdr.ScVal.scvU32(0) }));

events.push(ev("deposit", [X, A], { amount: i128(100n) }));
cRecv = cRecv.add(scalarMul(100n, G));

events.push(ev("merge", [A], {}));
cSpend = cSpend.add(cRecv); cRecv = IDENTITY;

// Incoming confidential transfer (B → me), built by the real witness builder.
const tw = buildTransferWitness({
  keys: bob, v: 1000n, r: randomScalar(), amount: 40n,
  pvkB: me.PVK, kAudR: scalarMul(7n, H), kAudS: scalarMul(9n, H),
});
const p = tw.payload;
events.push(ev("transfer", [B, A], {
  r_e_point: pnt(p.rE), v_tilde: fld(p.vTilde), sigma: fld(p.sigma), b_tilde: fld(p.bTilde),
  v_tilde_aud_r: fld(p.vAudR), r_tilde_aud_r: fld(p.rAudR), v_tilde_aud_s: fld(p.vAudS),
  b_tilde_aud_s: fld(p.bAudS), r_tilde_aud_s: fld(p.rAudS),
}));
cRecv = cRecv.add(p.cTransfer);

events.push(ev("merge", [A], {}));
cSpend = cSpend.add(cRecv); cRecv = IDENTITY; // spendable now opens (140, r_transfer)

// Delegation events come from the real witness builders: set_spender from my
// replayed opening (140, r_transfer), spender transfers from what S recovers
// out of the escrow — the same values the contract would emit.
const sKeys = deriveKeys(randomScalar(), addrF);
const audS = scalarMul(9n, H), audR = scalarMul(7n, H);
const spenderTransferFields = (q) => ({
  r_e_point: pnt(q.rE), v_tilde: fld(q.vTilde), sigma_a_new: fld(q.sigmaANew),
  v_tilde_aud_r: fld(q.vAudR), r_tilde_aud_r: fld(q.rAudR), v_tilde_aud_s: fld(q.vAudS),
  a_tilde_aud_s: fld(q.aAudS), r_tilde_aud_s: fld(q.rAudS),
});
const delegateAndSpend = (owner, v, r, escrow, amount, pvkRecipient) => {
  const sw = buildSetSpenderWitness({ keys: owner, v, r, amount: escrow, spender: S, yOp: sKeys.Y, kAudS: audS });
  const rec = recoverEscrowedDvk(sKeys.sk, addressToField(S), {
    escrowedDvk: sw.payload.escrowedDvk, aTilde: sw.payload.aTilde,
    allowanceSalt: sw.payload.sigmaA, allowanceCommitment: sw.payload.cA,
  });
  const stw = buildSpenderTransferWitness({
    keys: sKeys, allowance: { dvk: rec.dvk, sigmaA: sw.payload.sigmaA, v: rec.opening.v },
    amount, pvkRecipient, kAudR: audR, kAudS: audS,
  });
  return { sw, stw };
};

// set_spender: escrow 30 to S. Checkpoint: C_spend' = Com(110, r').
const preEscrowOk = commit(140n, tw.recipientView.rTransfer).equals(cSpend);
const mine = delegateAndSpend(me, 140n, tw.recipientView.rTransfer, 30n, 10n, deriveKeys(randomScalar(), addrF).PVK);
const sp = mine.sw.payload;
events.push(ev("set_spender", [A, S], {
  live_until_ledger: xdr.ScVal.scvU32(9999), r_e_point: pnt(sp.rE), sigma: fld(sp.sigma),
  b_tilde: fld(sp.bTilde), v_tilde_aud_s: fld(sp.vAudS), b_tilde_aud_s: fld(sp.bAudS),
  r_tilde_aud_s: fld(sp.rAudS), r_a_tilde_aud_s: fld(sp.raAudS),
}));
cSpend = sp.cSpendNew;
let cA = sp.cA; // held by the delegation

// S spends 10 of my allowance to C: my balances are untouched.
events.push(ev("spender_transfer", [S, A, C], spenderTransferFields(mine.stw.payload)));
cA = mine.stw.payload.cANew;

// Some other owner's spender pays ME 25: credit keyed by σ_a′.
const theirs = delegateAndSpend(deriveKeys(randomScalar(), addrF), 500n, randomScalar(), 60n, 25n, me.PVK);
events.push(ev("spender_transfer", [S, X, A], spenderTransferFields(theirs.stw.payload)));
cRecv = cRecv.add(theirs.stw.payload.cTransfer);

// Revoke: C_spend += C_a, the event carrying the delegation's CURRENT
// (a_tilde, salt) — the ones S's transfer wrote.
const revokeEv = ev("revoke_spender", [A, S], {
  a_tilde: fld(mine.stw.next.aTilde), allowance_salt: fld(mine.stw.next.sigmaA),
});
events.push(revokeEv);
cSpend = cSpend.add(cA);

// Clawback 15 with destination None: the field is OMITTED (soroban-sdk 28).
events.push(ev("clawback", [A], { amount: i128(15n) }));
cSpend = cSpend.add(cRecv).subtract(scalarMul(15n, G)); cRecv = IDENTITY;

events.push(ev("compliance_config_changed", [], { sac_passthrough: xdr.ScVal.scvBool(true) }));

const lateDeposit = ev("deposit", [X, A], { amount: i128(7n) });
events.push(lateDeposit);
cRecv = cRecv.add(scalarMul(7n, G));

const spendBeforeLastClawback = cSpend;

// Clawback 1 with destination Some(X).
events.push(ev("clawback", [A], { amount: i128(1n), destination: adr(X) }));
cSpend = cSpend.add(cRecv).subtract(scalarMul(1n, G)); cRecv = IDENTITY;

const finalSpend = cSpend, finalRecv = cRecv;

// --- Stub chain: serves `evs` once, then an empty tail from the cursor -------
const HEAD = 10 + seq + 1;
// `onchain` is the account the balance read returns, or a function standing in
// for confidentialBalance; `noCursor` serves events with no resume cursor.
function engineFor(evs, onchain, { store = new MemoryStore(), noCursor = false } = {}) {
  const client = {
    cfg: { contracts: { token: TOKEN } },
    server: {
      getHealth: async () => ({ oldestLedger: 1 }),
      getEvents: async (req) => ({
        events: req.cursor ? [] : evs,
        cursor: noCursor ? undefined : `${(BigInt(HEAD) << 32n).toString()}-0`,
        latestLedger: HEAD,
      }),
    },
    confidentialBalanceAt: async () => ({
      account: typeof onchain === "function" ? await onchain() : onchain,
      latestLedger: HEAD,
    }),
  };
  return new StateEngine({ client, store, keys: me, address: A, fromLedger: 1 });
}
const onchainOf = (spend, recv) => ({
  spendingKey: me.Y, viewingPublicKey: me.PVK, spendableBalance: spend, receivingBalance: recv, auditorId: 0,
});

console.log("full replay (all event types):");
check("scenario premise: my replayed opening before set_spender is (140, r_transfer)", preEscrowOk);
{
  const engine = engineFor(events, onchainOf(finalSpend, finalRecv));
  let state, err;
  try { state = await engine.sync(); } catch (e) { err = e; }
  check("sync verifies against contract-style commitments", !err, err?.message);
  check("spendable value = 140 − 30 + 20 + 25 − 15 + 7 − 1", state?.spendable.v === 146n, String(state?.spendable.v));
  check("receiving reset by the last clawback", state?.receiving.v === 0n && state?.receiving.r === 0n);
  check("registered", state?.registered === true);
  const opening = await engine.spendableForProof().catch((e) => e);
  check("spendableForProof returns the verified opening", opening?.v === 146n, String(opening?.message ?? ""));
}

console.log("decoded optional fields:");
{
  const { fetchEvents } = await import("../src/chain/events.ts");
  const server = {
    getEvents: async (req) => ({
      events: req.cursor ? [] : events,
      cursor: `${(BigInt(HEAD) << 32n).toString()}-0`,
      latestLedger: HEAD,
    }),
  };
  const { events: parsed } = await fetchEvents(
    { cfg: { contracts: { token: TOKEN } }, server },
    { startLedger: 1 },
  );
  const claws = parsed.filter((e) => e.type === "clawback");
  check("clawback with omitted destination → null", claws[0]?.destination === null);
  check("clawback with Some(destination) → address", claws[1]?.destination === X);
  const cfg = parsed.find((e) => e.type === "compliance_config_changed");
  check("compliance_config_changed: omitted policy → null, flag decoded", cfg?.policy === null && cfg?.sacPassthrough === true);
  const st = parsed.find((e) => e.type === "spender_transfer");
  check("spender_transfer topics: spender, from, to", st?.spender === S && st?.from === A && st?.to === C);
  check("every scenario event decoded", parsed.length === events.length, `${parsed.length}/${events.length}`);
}

console.log("divergence is loud and names the accumulator:");
{
  const engine = engineFor(events.filter((e) => e !== revokeEv), onchainOf(finalSpend, finalRecv));
  const err = await engine.sync().catch((e) => e);
  check("missed revoke_spender → StateDivergedError", err instanceof StateDivergedError, String(err));
  check("… on the spendable side only", err?.report?.spendableOk === false && err?.report?.receivingOk === true);
  const gate = await engine.spendableForProof().catch((e) => e);
  check("spendableForProof refuses a diverged spendable opening", gate instanceof StateDivergedError);
  // The error carries the secret openings: reachable from code, but never
  // picked up by serializers or error trackers.
  check("… state still readable from code", gate?.state?.spendable?.v !== undefined);
  check("… state is not enumerable", !Object.keys(gate).includes("state"));
  const json = (() => { try { return JSON.stringify(gate); } catch (e) { return e; } })();
  check("… JSON-serializes without the state", typeof json === "string" && !json.includes('"state"'), String(json));
  check("… message carries no blinding", !gate.message.includes(String(gate.state.spendable.r)), gate.message);
}
{
  // Stop before the final clawback, so the late deposit sits in receiving
  // locally; serve an on-chain receiving that never saw that deposit.
  const evs = events.slice(0, -1);
  const engine = engineFor(evs, onchainOf(spendBeforeLastClawback, IDENTITY));
  const err = await engine.sync().catch((e) => e);
  check("missed credit → receiving-side divergence", err instanceof StateDivergedError && err.report.receivingOk === false);
  check("… spendable still consistent, so proving is allowed", err?.report?.spendableOk === true);
  const opening = await engine.spendableForProof().catch((e) => e);
  check("spendableForProof gates on spendable only", !(opening instanceof Error));
}
{
  const engine = engineFor([], null);
  const err = await engine.sync().catch((e) => e);
  check("unregistered account with no on-chain record syncs clean", !(err instanceof Error), String(err));
}

console.log("a failed balance read is not a divergence:");
{
  const outage = new Error("simulate confidential_balance failed: 503 Service Unavailable");
  const engine = engineFor(events, async () => { throw outage; });
  const err = await engine.sync().catch((e) => e);
  check("sync surfaces the RPC error as-is", err === outage, String(err));
  const gate = await engine.spendableForProof().catch((e) => e);
  check("spendableForProof surfaces it too", gate === outage, String(gate));
}

console.log("no resume cursor → nothing applied or saved:");
{
  const store = new MemoryStore();
  const engine = engineFor(events, onchainOf(finalSpend, finalRecv), { store, noCursor: true });
  const err = await engine.sync().catch((e) => e);
  check(
    "sync refuses events it could not resume past",
    err instanceof Error && !(err instanceof StateDivergedError) && /no resume cursor/.test(err.message),
    String(err),
  );
  check("… and saves no state", (await store.load(A)) === null);
}
{
  const engine = engineFor([], null, { noCursor: true });
  const err = await engine.sync().catch((e) => e);
  check("an empty fetch without a cursor is harmless", !(err instanceof Error), String(err));
}

console.log("a mismatch only counts at the fetched ledger:");
// The i-th getEvents call serves `fetches[i]` (afterwards: nothing new at the
// last ledger), each with a cursor at its own latestLedger; the i-th balance
// read serves `reads[i]` (the last one repeats). `calls` counts both.
function scriptedEngine(fetches, reads) {
  const calls = { fetches: 0, reads: 0 };
  const client = {
    cfg: { contracts: { token: TOKEN } },
    server: {
      getHealth: async () => ({ oldestLedger: 1 }),
      getEvents: async () => {
        const f = fetches[calls.fetches++] ?? { events: [], ledger: fetches.at(-1).ledger };
        return { events: f.events, cursor: `${(BigInt(f.ledger) << 32n).toString()}-0`, latestLedger: f.ledger };
      },
    },
    confidentialBalanceAt: async () => {
      const r = reads[Math.min(calls.reads++, reads.length - 1)];
      return { account: r.account, latestLedger: r.ledger };
    },
  };
  const engine = new StateEngine({ client, store: new MemoryStore(), keys: me, address: A, fromLedger: 1 });
  return { engine, calls };
}
const final = onchainOf(finalSpend, finalRecv);
const lastEv = events.at(-1);
{
  const { engine, calls } = scriptedEngine(
    [{ events: events.filter((e) => e !== revokeEv), ledger: HEAD }],
    [{ account: final, ledger: HEAD }],
  );
  const err = await engine.sync().catch((e) => e);
  check("same ledger + mismatch → StateDivergedError", err instanceof StateDivergedError, String(err));
  check("… with no re-fetch", calls.fetches === 1 && calls.reads === 1, JSON.stringify(calls));
}
{
  // The final clawback lands after the first fetch; the read already sees it.
  const { engine, calls } = scriptedEngine(
    [
      { events: events.slice(0, -1), ledger: HEAD },
      { events: [lastEv], ledger: HEAD + 1 },
    ],
    [{ account: final, ledger: HEAD + 1 }],
  );
  const res = await engine.sync().catch((e) => e);
  check("read ahead of the fetch → incremental sync, then clean", !(res instanceof Error), String(res));
  check("… after exactly one more fetch", calls.fetches === 2 && calls.reads === 2, JSON.stringify(calls));
  check("… and the late event applied once", res?.spendable?.v === 146n && res?.syncedLedger === HEAD + 1);
}
{
  // A lagging node serves the balance from before the final clawback.
  const { engine, calls } = scriptedEngine(
    [{ events, ledger: HEAD }],
    [
      { account: onchainOf(spendBeforeLastClawback, finalRecv.add(scalarMul(7n, G))), ledger: HEAD - 1 },
      { account: final, ledger: HEAD },
    ],
  );
  const res = await engine.sync().catch((e) => e);
  check("stale read → re-read only, then clean", !(res instanceof Error), String(res));
  check("… without re-fetching", calls.fetches === 1 && calls.reads === 2, JSON.stringify(calls));
}
{
  const { engine, calls } = scriptedEngine([{ events, ledger: HEAD }], [{ account: final, ledger: HEAD + 3 }]);
  const res = await engine.sync().catch((e) => e);
  check("a match at a later ledger verifies without re-fetching", !(res instanceof Error) && calls.fetches === 1, String(res));
}
{
  // Every read stays one ledger ahead of every fetch and never matches.
  const { engine, calls } = scriptedEngine(
    [{ events: events.slice(0, -1), ledger: HEAD }],
    [{ account: final, ledger: HEAD + 1 }],
  );
  const err = await engine.sync().catch((e) => e);
  check(
    "never lining up → StateUnverifiedError, not a divergence",
    err instanceof StateUnverifiedError && !(err instanceof StateDivergedError),
    String(err),
  );
  check("… after a capped number of reads", calls.reads === 5 && calls.fetches === 5, JSON.stringify(calls));
  check("… reporting both ledgers", err?.syncedLedger === HEAD && err?.balanceLedger === HEAD + 1);
  check("… without claiming a missed event", !/missed/.test(err?.message ?? ""), err?.message);

  const gate = await engine.spendableForProof().catch((e) => e);
  check(
    "spendableForProof: mismatch at a newer ledger → sync first, not diverged",
    gate instanceof StateUnverifiedError && /sync\(\) before proving/.test(gate.message),
    String(gate),
  );
}

console.log(`\nreplay: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
