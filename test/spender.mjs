// Spender-side wallet test (no proving, no network): SpenderWallet and the
// owner's StateEngine.delegation() read a SpenderDelegation entry through the
// REAL ChainClient read path (simulate → parseDelegation, 3504 → null), served
// by a stub chain that encodes entries exactly as the contract's contracttype
// does. Entries are produced by the real witness builders and advanced the
// way storage.rs advances them, so the lifecycle set_spender →
// spender_transfer ×2 → revoke_spender is tracked from storage alone.
import { xdr, Address, Keypair } from "@stellar/stellar-sdk";

import { deriveKeys } from "../src/crypto/keys.ts";
import { addressToField } from "../src/crypto/address.ts";
import { H, commit, pointCoords, pointToBytes, pointsWithX, scalarMul } from "../src/crypto/grumpkin.ts";
import { randomScalar, toBytes32BE } from "../src/crypto/field.ts";
import { buildSetSpenderWitness } from "../src/witness/set-spender.ts";
import { buildSpenderTransferWitness } from "../src/witness/spender-transfer.ts";
import { ChainClient, SimulationFailedError, parseDelegation } from "../src/chain/client.ts";
import { submitSetSpender } from "../src/chain/contract.ts";
import { escrowedDvkToBytes, scvStruct } from "../src/chain/payload.ts";
import {
  DEFAULT_EXPIRY_WARNING_LEDGERS,
  DelegationExpiredError,
  DelegationNotFoundError,
  DelegationUnreadableError,
  SpenderWallet,
  delegationStatus,
} from "../src/state/spender.ts";
import { StateEngine } from "../src/state/engine.ts";
import { MemoryStore } from "../src/state/store.ts";

let pass = 0, fail = 0;
function check(name, cond, detail) {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.error(`  ✗ ${name}${detail ? `\n      ${detail}` : ""}`); }
}
const throwsAs = async (fn, cls) => {
  try { await fn(); return false; } catch (e) { return e instanceof cls ? e : false; }
};

const TOKEN = "CCREDIB3DG3IBVUKBL7QMEK4MTPSTODR7MQ34QY4SQ5LZ5L4WFWNVNXG";
const addrF = addressToField(TOKEN);
const OWNER = Keypair.random().publicKey();
const SPENDER = Keypair.random().publicKey();
const owner = deriveKeys(randomScalar(), addrF);
const spender = deriveKeys(randomScalar(), addrF);
const audS = scalarMul(11n, H);

// --- Stub chain: entries keyed `${owner}|${spender}` at a settable ledger ----
const entries = new Map();
let ledger = 1000;
const encodeEntry = (e) =>
  scvStruct({
    allowance_commitment: xdr.ScVal.scvBytes(Buffer.from(pointToBytes(e.allowanceCommitment))),
    a_tilde: xdr.ScVal.scvBytes(Buffer.from(toBytes32BE(e.aTilde))),
    escrowed_dvk: xdr.ScVal.scvBytes(Buffer.from(escrowedDvkToBytes(e.escrowedDvk))),
    allowance_salt: xdr.ScVal.scvBytes(Buffer.from(toBytes32BE(e.allowanceSalt))),
    live_until_ledger: xdr.ScVal.scvU32(e.liveUntilLedger),
  });
const chain = Object.create(ChainClient.prototype);
Object.assign(chain, {
  cfg: { contracts: { token: TOKEN } },
  async simulateAt(_contract, method, args) {
    const [o, s] = args.map((a) => Address.fromScVal(a).toString());
    const e = entries.get(`${o}|${s}`);
    if (method === "get_spender_delegation") {
      if (!e) throw new SimulationFailedError(method, "HostError: Error(Contract, #3504)", ledger);
      return { retval: encodeEntry(e), latestLedger: ledger };
    }
    if (method === "is_spender") return { retval: xdr.ScVal.scvBool(!!e && ledger <= e.liveUntilLedger), latestLedger: ledger };
    throw new Error(`unexpected simulate ${method}`);
  },
});
const key = `${OWNER}|${SPENDER}`;

// set_spender as the contract stores it (storage.rs::set_spender).
const sw = buildSetSpenderWitness({
  keys: owner, v: 1000n, r: randomScalar(), amount: 300n, spender: SPENDER, yOp: spender.Y, kAudS: audS,
});
const LIVE_UNTIL = ledger + 100_000;
entries.set(key, {
  allowanceCommitment: sw.payload.cA,
  aTilde: sw.payload.aTilde,
  escrowedDvk: sw.payload.escrowedDvk,
  allowanceSalt: sw.payload.sigmaA,
  liveUntilLedger: LIVE_UNTIL,
});

const wallet = new SpenderWallet({ client: chain, keys: spender, address: SPENDER });
const ownerEngine = new StateEngine({
  client: chain, store: new MemoryStore(), keys: owner, address: OWNER, fromLedger: 1,
});

console.log("spender reads its allowance from the entry alone:");
{
  const a = await wallet.allowance(OWNER);
  check("allowance value and blinding recovered", a?.v === 300n && a?.r === sw.allowance.r);
  check("dvk recovered from the escrow equals the owner's dvk", a?.dvk === sw.allowance.dvk);
  check("opening re-commits to on-chain C_a", a && commit(a.v, a.r).equals(a.cA));
  check("expiry ledger surfaced", a?.liveUntilLedger === LIVE_UNTIL && a?.ledgersRemaining === LIVE_UNTIL - ledger);
  check("status live", a?.status === "live");
  check("is_spender", await chain.isSpender(OWNER, SPENDER));
  const o = await ownerEngine.delegation(SPENDER);
  check("owner's view opens the same allowance under its own dvk", o?.v === 300n && o?.dvk === a?.dvk);
  check("owner's view: status live under the default horizon", o?.status === "live");
  const wideHorizon = new StateEngine({
    client: chain, store: new MemoryStore(), keys: owner, address: OWNER, fromLedger: 1,
    expiryWarningLedgers: LIVE_UNTIL - ledger,
  });
  check("owner's view takes a warning horizon", (await wideHorizon.delegation(SPENDER))?.status === "expiring");
}

console.log("escrow sign ambiguity (R_x stores no y):");
{
  // Only R.x is stored and ecdh absorbs S.y, so half of all escrows decrypt
  // only on the second square root. See both cases, and that each recovers.
  const seen = { first: 0, second: 0 }, failed = [];
  for (let i = 0; i < 24 && (seen.first === 0 || seen.second === 0 || i < 8); i++) {
    const w = buildSetSpenderWitness({
      keys: owner, v: 50n, r: 0n, amount: 5n, spender: SPENDER, yOp: spender.Y, kAudS: audS,
    });
    const [p0] = pointsWithX(w.payload.escrowedDvk.rX);
    if (p0.equals(w.payload.rE)) seen.first++; else seen.second++;
    entries.set(key, {
      allowanceCommitment: w.payload.cA, aTilde: w.payload.aTilde, escrowedDvk: w.payload.escrowedDvk,
      allowanceSalt: w.payload.sigmaA, liveUntilLedger: LIVE_UNTIL,
    });
    const a = await wallet.allowance(OWNER);
    if (a?.v !== 5n || a?.dvk !== w.allowance.dvk) failed.push(i);
  }
  check(`both roots exercised (R_e first ${seen.first}×, second ${seen.second}×)`, seen.first > 0 && seen.second > 0);
  check("every escrow recovered on its correct root", failed.length === 0, `failed at ${failed}`);
  const lifted = Array.from({ length: 20 }, (_, i) => BigInt(i + 1)).map(pointsWithX);
  check(
    "pointsWithX: null off the curve, else the pair ±P on x",
    lifted.some((r) => r === null) &&
      lifted.filter(Boolean).every(([p, q], _, all) => p.equals(q.negate()) && pointCoords(p).x === pointCoords(q).x) &&
      lifted.filter(Boolean).length > 0,
  );
}

console.log("expiry is surfaced, and expired value still counts:");
{
  entries.set(key, {
    allowanceCommitment: sw.payload.cA, aTilde: sw.payload.aTilde, escrowedDvk: sw.payload.escrowedDvk,
    allowanceSalt: sw.payload.sigmaA, liveUntilLedger: LIVE_UNTIL,
  });
  ledger = LIVE_UNTIL - 10;
  const soon = await wallet.allowance(OWNER);
  check("inside the warning horizon → expiring", soon?.status === "expiring" && soon?.ledgersRemaining === 10);
  check("expiring is still spendable", (await wallet.allowanceForProof(OWNER).catch((e) => e))?.v === 300n);
  // The contract accepts a spend at ledger ≤ live_until, and a transaction
  // lands at the read ledger + 1 at the earliest.
  ledger = LIVE_UNTIL - 1;
  const last = await wallet.allowance(OWNER);
  check("one ledger before expiry: still spendable (a spend can land at live_until)",
    last?.status === "expiring" && last?.ledgersRemaining === 1 && (await wallet.allowanceForProof(OWNER).catch((e) => e))?.v === 300n);
  ledger = LIVE_UNTIL;
  const atExpiry = await wallet.allowance(OWNER);
  check("read at live_until → expired: no spend can land by then", atExpiry?.status === "expired" && atExpiry?.ledgersRemaining === 0);
  const errAt = await throwsAs(() => wallet.allowanceForProof(OWNER), DelegationExpiredError);
  check("allowanceForProof refuses it at live_until", errAt && errAt.ledger === LIVE_UNTIL);
  check("delegationStatus boundary", delegationStatus(100, 99, 0) === "live" && delegationStatus(100, 100, 0) === "expired");
  ledger = LIVE_UNTIL + 1;
  const gone = await wallet.allowance(OWNER);
  check("past expiry → expired, value still escrowed", gone?.status === "expired" && gone?.v === 300n);
  check("is_spender false once expired", !(await chain.isSpender(OWNER, SPENDER)));
  const err = await throwsAs(() => wallet.allowanceForProof(OWNER), DelegationExpiredError);
  check("allowanceForProof refuses an expired delegation", err && err.liveUntilLedger === LIVE_UNTIL && err.ledger === LIVE_UNTIL + 1);
  check("custom warning horizon", delegationStatus(100, 50, 10) === "live" && delegationStatus(100, 95, 10) === "expiring");
  check("default horizon is one day of ledgers", DEFAULT_EXPIRY_WARNING_LEDGERS === 17_280);
  ledger = 1000;
}

console.log("lifecycle tracked from storage (set → spend → spend → revoke):");
{
  // storage.rs::confidential_transfer_from rewrites C_a, a_tilde and the salt;
  // escrowed_dvk and live_until_ledger are untouched.
  const spend = async (amount) => {
    const a = await wallet.allowanceForProof(OWNER);
    const w = buildSpenderTransferWitness({
      keys: spender, allowance: a, amount,
      pvkRecipient: deriveKeys(randomScalar(), addrF).PVK, kAudR: audS, kAudS: audS,
    });
    const prev = entries.get(key);
    entries.set(key, { ...prev, allowanceCommitment: w.payload.cANew, aTilde: w.payload.aTildeNew, allowanceSalt: w.payload.sigmaANew });
    return w;
  };
  const w1 = await spend(120n);
  const a1 = await wallet.allowance(OWNER);
  check("after one spend: allowance = 180, opening = witness.next", a1?.v === 180n && a1?.r === w1.next.r);
  check("salt rotated to σ_a'", a1?.sigmaA === w1.payload.sigmaANew && a1?.sigmaA !== sw.payload.sigmaA);
  const w2 = await spend(180n);
  const a2 = await wallet.allowance(OWNER);
  check("spending the rest leaves a zero allowance", a2?.v === 0n && commit(0n, a2.r).equals(a2.cA));
  check("owner's view follows the spender's transfers", (await ownerEngine.delegation(SPENDER))?.v === 0n);
  check("witness salts never repeat", new Set([sw.payload.sigmaA, w1.payload.sigmaANew, w2.payload.sigmaANew]).size === 3);
  entries.delete(key); // storage.rs::revoke_spender deletes the entry
  check("revoked: allowance() → null", (await wallet.allowance(OWNER)) === null);
  check("revoked: owner's view → null", (await ownerEngine.delegation(SPENDER)) === null);
  check("revoked: allowanceForProof → DelegationNotFoundError", !!(await throwsAs(() => wallet.allowanceForProof(OWNER), DelegationNotFoundError)));
  check("revoked: is_spender false", !(await chain.isSpender(OWNER, SPENDER)));
}

console.log("foreign keys and contract mismatches are loud:");
{
  entries.set(key, {
    allowanceCommitment: sw.payload.cA, aTilde: sw.payload.aTilde, escrowedDvk: sw.payload.escrowedDvk,
    allowanceSalt: sw.payload.sigmaA, liveUntilLedger: LIVE_UNTIL,
  });
  const intruder = new SpenderWallet({ client: chain, keys: deriveKeys(randomScalar(), addrF), address: SPENDER });
  check("another key set cannot open the escrow → DelegationUnreadableError", !!(await throwsAs(() => intruder.allowance(OWNER), DelegationUnreadableError)));
  const wrongAddress = new SpenderWallet({ client: chain, keys: spender, address: OWNER });
  entries.set(`${OWNER}|${OWNER}`, entries.get(key));
  check("op_i is the spender's address: the escrow does not open under another", !!(await throwsAs(() => wrongAddress.allowance(OWNER), DelegationUnreadableError)));
  entries.delete(`${OWNER}|${OWNER}`);
  const notOwner = new StateEngine({
    client: chain, store: new MemoryStore(), keys: deriveKeys(randomScalar(), addrF), address: OWNER, fromLedger: 1,
  });
  check("owner view under the wrong keys → DelegationUnreadableError", !!(await throwsAs(() => notOwner.delegation(SPENDER), DelegationUnreadableError)));
  const renamed = xdr.ScVal.scvMap(
    encodeEntry(entries.get(key)).map().map((e) =>
      e.key().sym().toString() === "a_tilde" ? new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("allowance_ciphertext"), val: e.val() }) : e,
    ),
  );
  let renameErr;
  try { parseDelegation(renamed); } catch (e) { renameErr = e; }
  check("a renamed contract field throws, naming it", /missing aTilde/.test(renameErr?.message ?? ""), renameErr?.message);
  const outage = new SimulationFailedError("get_spender_delegation", "HostError: Error(Storage, MissingValue)", ledger);
  const flaky = Object.assign(Object.create(ChainClient.prototype), { cfg: chain.cfg, simulateAt: async () => { throw outage; } });
  check(
    "a non-3504 failure propagates instead of reading as revoked",
    (await new SpenderWallet({ client: flaky, keys: spender, address: SPENDER }).allowance(OWNER).catch((e) => e)) === outage,
  );
}

console.log("set_spender refuses a lifetime nobody can spend in:");
{
  const invoked = [];
  const submitter = Object.assign(Object.create(ChainClient.prototype), {
    cfg: chain.cfg,
    server: { getHealth: async () => ({ latestLedger: ledger }) },
    invoke: async (_contract, method) => { invoked.push(method); return { status: "SUCCESS" }; },
  });
  const submit = (liveUntil) =>
    submitSetSpender(submitter, null, OWNER, SPENDER, liveUntil, sw, new Uint8Array(0)).then(() => "submitted", (e) => e);
  const past = await submit(ledger - 1);
  check("a past liveUntilLedger is refused", past instanceof Error && /no ledger to spend in/.test(past.message), past?.message);
  check("the latest ledger is refused", (await submit(ledger)) instanceof Error);
  check("latest + 1 is refused (a spender reading it there sees it expired)", (await submit(ledger + 1)) instanceof Error);
  check("… and none of them reached the chain", invoked.length === 0);
  check("latest + 2 is submitted", (await submit(ledger + 2)) === "submitted" && invoked[0] === "set_spender");
}

console.log("discovery from set_spender events:");
{
  const OTHER_OWNER = Keypair.random().publicKey();
  const REVOKED_OWNER = Keypair.random().publicKey();
  const other = deriveKeys(randomScalar(), addrF);
  const ow = buildSetSpenderWitness({ keys: other, v: 70n, r: 0n, amount: 70n, spender: SPENDER, yOp: spender.Y, kAudS: audS });
  entries.set(`${OTHER_OWNER}|${SPENDER}`, {
    allowanceCommitment: ow.payload.cA, aTilde: ow.payload.aTilde, escrowedDvk: ow.payload.escrowedDvk,
    allowanceSalt: ow.payload.sigmaA, liveUntilLedger: LIVE_UNTIL,
  });
  const setSpenderEvent = (account, sp, n) => ({
    id: `${(BigInt(900 + n) << 32n).toString()}-0`, ledger: 900 + n, txHash: `tx${n}`,
    topic: [xdr.ScVal.scvSymbol("set_spender"), new Address(account).toScVal(), new Address(sp).toScVal()],
    value: scvStruct({
      live_until_ledger: xdr.ScVal.scvU32(LIVE_UNTIL), r_e_point: xdr.ScVal.scvBytes(Buffer.from(pointToBytes(sw.payload.rE))),
      ...Object.fromEntries(
        ["sigma", "b_tilde", "v_tilde_aud_s", "b_tilde_aud_s", "r_tilde_aud_s", "r_a_tilde_aud_s"].map((k) => [
          k, xdr.ScVal.scvBytes(Buffer.from(toBytes32BE(1n))),
        ]),
      ),
    }),
  });
  chain.server = {
    getHealth: async () => ({ oldestLedger: 1 }),
    getEvents: async (req) => ({
      events: req.cursor ? [] : [
        setSpenderEvent(OWNER, SPENDER, 1),
        setSpenderEvent(OTHER_OWNER, SPENDER, 2),
        setSpenderEvent(REVOKED_OWNER, SPENDER, 3), // entry since deleted
        setSpenderEvent(OWNER, Keypair.random().publicKey(), 4), // someone else's spender
        setSpenderEvent(OWNER, SPENDER, 5), // re-delegation after a revoke
      ],
      cursor: `${(BigInt(ledger) << 32n).toString()}-0`,
      latestLedger: ledger,
    }),
  };
  const found = await wallet.allowances({ fromLedger: 1 });
  check("finds each live entry once, skips revoked and foreign ones", found.length === 2, JSON.stringify(found.map((a) => a.owner)));
  check("… with each owner's allowance", new Set(found.map((a) => `${a.owner}:${a.v}`)).has(`${OTHER_OWNER}:70`) && found.some((a) => a.owner === OWNER && a.v === 300n));
}

console.log(`\nspender: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
