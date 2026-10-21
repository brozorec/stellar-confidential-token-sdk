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
import { G, H, IDENTITY, commit, ecdh, scalarMul, pointToBytes } from "../src/crypto/grumpkin.ts";
import { randomScalar, toBytes32BE } from "../src/crypto/field.ts";
import { addressToField } from "../src/crypto/address.ts";
import {
  deriveAllowR,
  deriveSpendR,
  deriveTransferBlind,
  dvkFromVkOp,
  encryptAllowance,
  encryptAmount,
  encryptBalance,
} from "../src/crypto/poseidon2.ts";
import { buildTransferWitness } from "../src/witness/transfer.ts";
import { StateEngine, StateDivergedError } from "../src/state/engine.ts";
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
const junk = () => fld(randomScalar());
const junkPoint = () => pnt(scalarMul(randomScalar(), H));

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

// set_spender: escrow 30 to S. Checkpoint: C_spend' = Com(110, r').
const dvk = dvkFromVkOp(me.vk, addressToField(S));
const sigma = randomScalar(), sigmaA = randomScalar();
events.push(ev("set_spender", [A, S], {
  live_until_ledger: xdr.ScVal.scvU32(9999), r_e_point: junkPoint(), sigma: fld(sigma),
  b_tilde: fld(encryptBalance(110n, me.vk, sigma)), v_tilde_aud_s: junk(), b_tilde_aud_s: junk(),
  r_tilde_aud_s: junk(), r_a_tilde_aud_s: junk(),
}));
cSpend = commit(110n, deriveSpendR(me.vk, sigma));
let allowance = { v: 30n, r: deriveAllowR(dvk, sigmaA) }; // C_a, held by the delegation

// S spends 10 of my allowance to C: my balances are untouched.
const sigmaA2 = randomScalar();
events.push(ev("spender_transfer", [S, A, C], {
  r_e_point: junkPoint(), v_tilde: junk(), sigma_a_new: fld(sigmaA2), v_tilde_aud_r: junk(),
  r_tilde_aud_r: junk(), v_tilde_aud_s: junk(), a_tilde_aud_s: junk(), r_tilde_aud_s: junk(),
}));
allowance = { v: 20n, r: deriveAllowR(dvk, sigmaA2) };

// Some other owner's spender pays ME 25: credit keyed by σ_a′.
const rEs = randomScalar(), sigmaIn = randomScalar();
const sIn = ecdh(rEs, me.PVK);
events.push(ev("spender_transfer", [S, X, A], {
  r_e_point: pnt(scalarMul(rEs, H)), v_tilde: fld(encryptAmount(25n, sIn, sigmaIn)),
  sigma_a_new: fld(sigmaIn), v_tilde_aud_r: junk(), r_tilde_aud_r: junk(),
  v_tilde_aud_s: junk(), a_tilde_aud_s: junk(), r_tilde_aud_s: junk(),
}));
cRecv = cRecv.add(commit(25n, deriveTransferBlind(sIn, sigmaIn)));

// Revoke: C_spend += C_a (the delegation's CURRENT allowance and salt).
const revokeEv = ev("revoke_spender", [A, S], {
  a_tilde: fld(encryptAllowance(allowance.v, dvk, sigmaA2)), allowance_salt: fld(sigmaA2),
});
events.push(revokeEv);
cSpend = cSpend.add(commit(allowance.v, allowance.r));

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
function engineFor(evs, onchain) {
  const client = {
    cfg: { contracts: { token: TOKEN } },
    server: {
      getHealth: async () => ({ oldestLedger: 1 }),
      getEvents: async (req) => ({
        events: req.cursor ? [] : evs,
        cursor: `${(BigInt(HEAD) << 32n).toString()}-0`,
        latestLedger: HEAD,
      }),
    },
    confidentialBalance: async () => onchain,
  };
  return new StateEngine({ client, store: new MemoryStore(), keys: me, address: A, fromLedger: 1 });
}
const onchainOf = (spend, recv) => ({
  spendingKey: me.Y, viewingPublicKey: me.PVK, spendableBalance: spend, receivingBalance: recv, auditorId: 0,
});

console.log("full replay (all event types):");
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

console.log(`\nreplay: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
