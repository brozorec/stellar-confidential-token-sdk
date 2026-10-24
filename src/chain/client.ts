/**
 * Soroban RPC client: read-only simulation, full invoke (build → simulate →
 * assemble → sign → send → poll), and typed reads of confidential state.
 *
 * No indexer. State that the protocol exposes only through events is read with
 * the RPC `getEvents` API (see `events.ts`), accepting its ~7-day retention
 * window — the central trade-off of this design.
 */

import {
  xdr,
  Address,
  Account,
  Contract,
  Keypair,
  TransactionBuilder,
  BASE_FEE,
  rpc,
} from "@stellar/stellar-sdk";

import { pointFromBytes, type Point } from "../crypto/grumpkin.js";
import { fromBytesBE } from "../crypto/field.js";
import type { EscrowedDvk } from "../crypto/delegation.js";
import { parseContractErrorCode } from "./errors.js";

/** Source used for read-only simulation; never signs, never pays. */
const NULL_ACCOUNT = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/** `ConfidentialTokenError::AccountNotRegistered` — `confidential_balance` on an unknown account. */
const ACCOUNT_NOT_REGISTERED = 3501;

/** `ConfidentialTokenError::DelegationNotFound` — `get_spender_delegation` on an absent pair. */
const DELEGATION_NOT_FOUND = 3504;

const POLL_INTERVAL_MS = 2000;
const MAX_POLL_ATTEMPTS = 60;

/**
 * Minimal transaction signer. A Node script wraps a {@link Keypair} via
 * {@link keypairSigner}; the web app wraps Freighter's `signTransaction`.
 */
export interface Signer {
  /** G-address of the signer (transaction source / auth principal). */
  publicKey: string;
  /** Sign an assembled transaction (base64 XDR) and return signed base64 XDR. */
  sign(txXdrBase64: string): Promise<string>;
}

export interface ContractIds {
  token: string;
  verifier: string;
  auditor: string;
}

export interface ChainConfig {
  rpcUrl: string;
  networkPassphrase: string;
  contracts: ContractIds;
}

export interface InvokeResult {
  hash: string;
  status: string;
  /** Return value of the invoked function (if any). */
  returnValue?: xdr.ScVal;
}

/** On-chain confidential account (`confidential_balance` return value). */
export interface OnChainAccount {
  spendingKey: Point;
  viewingPublicKey: Point;
  spendableBalance: Point;
  receivingBalance: Point;
  auditorId: number;
}

/** On-chain `(owner, spender)` delegation (`get_spender_delegation` return value). */
export interface OnChainDelegation {
  /** `C_a = Com(v_a, r_a)`. */
  allowanceCommitment: Point;
  /** `a_tilde = v_a + Poseidon2(ENCRYPTED_ALLOWANCE, dvk, σ_a)`. */
  aTilde: bigint;
  /** ECDH escrow of `dvk` under the spender's spending key. */
  escrowedDvk: EscrowedDvk;
  /** `σ_a`, the salt `C_a` and `a_tilde` are derived under. */
  allowanceSalt: bigint;
  /** Spendable while `ledger ≤ liveUntilLedger`; the value stays escrowed after. */
  liveUntilLedger: number;
}

/**
 * The RPC rejected a simulation (a contract panic, a host or storage error).
 * The message keeps the `simulate <method> failed: <host error>` form that
 * `humanizeContractError` parses; `latestLedger` is the ledger it ran against.
 */
export class SimulationFailedError extends Error {
  constructor(
    method: string,
    hostError: string,
    readonly latestLedger: number,
  ) {
    super(`simulate ${method} failed: ${hostError}`);
    this.name = "SimulationFailedError";
  }
}

export function keypairSigner(secret: string, networkPassphrase: string): Signer {
  const kp = Keypair.fromSecret(secret);
  return {
    publicKey: kp.publicKey(),
    async sign(txXdrBase64: string): Promise<string> {
      const tx = TransactionBuilder.fromXDR(txXdrBase64, networkPassphrase);
      tx.sign(kp);
      return tx.toXDR();
    },
  };
}

export class ChainClient {
  readonly server: rpc.Server;

  constructor(readonly cfg: ChainConfig) {
    this.server = new rpc.Server(cfg.rpcUrl, {
      allowHttp: cfg.rpcUrl.startsWith("http://"),
    });
  }

  // ----- reads -------------------------------------------------------------

  /** Simulate a read-only call and return its raw `ScVal` result. */
  async simulate(contractId: string, method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    return (await this.simulateAt(contractId, method, args)).retval;
  }

  /**
   * {@link simulate}, plus the ledger the simulation ran against (the
   * response's `latestLedger`) — for reads that are compared with an event
   * fetch through a given ledger. A rejected simulation throws a
   * {@link SimulationFailedError} carrying that ledger too.
   */
  async simulateAt(
    contractId: string,
    method: string,
    args: xdr.ScVal[],
  ): Promise<{ retval: xdr.ScVal; latestLedger: number }> {
    const account = await this.server
      .getAccount(NULL_ACCOUNT)
      .catch(() => new Account(NULL_ACCOUNT, "0"));
    const tx = new TransactionBuilder(account, {
      fee: BASE_FEE,
      networkPassphrase: this.cfg.networkPassphrase,
    })
      .addOperation(new Contract(contractId).call(method, ...args))
      .setTimeout(30)
      .build();

    const sim = await this.server.simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim)) {
      throw new SimulationFailedError(method, sim.error, sim.latestLedger);
    }
    const ok = sim as rpc.Api.SimulateTransactionSuccessResponse;
    if (!ok.result) throw new Error(`simulate ${method}: no result`);
    return { retval: ok.result.retval, latestLedger: ok.latestLedger };
  }

  /**
   * Read a confidential account, or `null` if `address` is not registered.
   *
   * Only the contract's `AccountNotRegistered` panic means "not registered".
   * Every other simulate failure (transport, rate limit, an archived entry,
   * any other contract error) propagates: reporting it as `null` would make an
   * unreachable chain look like an empty account, and the state engine's
   * consistency check would then call a healthy local state diverged. A
   * {@link parseAccount} failure is a real SDK/contract mismatch and propagates
   * too — swallowing it would report every account as unregistered after a
   * contract-side field rename.
   */
  async confidentialBalance(address: string): Promise<OnChainAccount | null> {
    return (await this.confidentialBalanceAt(address)).account;
  }

  /**
   * {@link confidentialBalance}, plus the ledger the read ran against — what
   * `StateEngine` compares with the ledger its events were fetched through.
   */
  async confidentialBalanceAt(
    address: string,
  ): Promise<{ account: OnChainAccount | null; latestLedger: number }> {
    let read: { retval: xdr.ScVal; latestLedger: number };
    try {
      read = await this.simulateAt(this.cfg.contracts.token, "confidential_balance", [
        new Address(address).toScVal(),
      ]);
    } catch (e) {
      if (e instanceof SimulationFailedError && parseContractErrorCode(e.message) === ACCOUNT_NOT_REGISTERED) {
        return { account: null, latestLedger: e.latestLedger };
      }
      throw e;
    }
    return { account: parseAccount(read.retval), latestLedger: read.latestLedger };
  }

  async isRegistered(address: string): Promise<boolean> {
    return (await this.confidentialBalance(address)) !== null;
  }

  /**
   * Read the `(owner, spender)` delegation, or `null` if none exists — never
   * delegated, or revoked. An expired entry is returned: its value is still
   * escrowed until revoked. Only `DelegationNotFound` maps to `null`; every
   * other failure propagates, as in {@link confidentialBalance}.
   */
  async spenderDelegation(owner: string, spender: string): Promise<OnChainDelegation | null> {
    return (await this.spenderDelegationAt(owner, spender)).delegation;
  }

  /**
   * {@link spenderDelegation}, plus the ledger the read ran against — what an
   * expiry check compares `liveUntilLedger` with.
   */
  async spenderDelegationAt(
    owner: string,
    spender: string,
  ): Promise<{ delegation: OnChainDelegation | null; latestLedger: number }> {
    let read: { retval: xdr.ScVal; latestLedger: number };
    try {
      read = await this.simulateAt(this.cfg.contracts.token, "get_spender_delegation", [
        new Address(owner).toScVal(),
        new Address(spender).toScVal(),
      ]);
    } catch (e) {
      if (e instanceof SimulationFailedError && parseContractErrorCode(e.message) === DELEGATION_NOT_FOUND) {
        return { delegation: null, latestLedger: e.latestLedger };
      }
      throw e;
    }
    return { delegation: parseDelegation(read.retval), latestLedger: read.latestLedger };
  }

  /** `is_spender(account, spender)`: a delegation exists AND is not expired. */
  async isSpender(owner: string, spender: string): Promise<boolean> {
    const retval = await this.simulate(this.cfg.contracts.token, "is_spender", [
      new Address(owner).toScVal(),
      new Address(spender).toScVal(),
    ]);
    return retval.b();
  }

  /** Fetch auditor key `K_aud` (BytesN<64>) for an `auditor_id`. */
  async auditorKey(auditorId: number): Promise<Point> {
    const retval = await this.simulate(this.cfg.contracts.auditor, "get_key", [
      xdr.ScVal.scvU32(auditorId),
    ]);
    return pointFromBytes(new Uint8Array(retval.bytes()));
  }

  async latestLedger(): Promise<number> {
    return (await this.server.getHealth()).latestLedger;
  }

  // ----- writes ------------------------------------------------------------

  /**
   * Build, simulate, assemble, sign, submit, and poll a contract invocation.
   * Auth is taken from simulation; for these operations the source account is the
   * sole auth principal, so a single signature suffices.
   */
  async invoke(
    contractId: string,
    method: string,
    args: xdr.ScVal[],
    signer: Signer,
  ): Promise<InvokeResult> {
    const source = await this.server.getAccount(signer.publicKey);
    const tx = new TransactionBuilder(source, {
      fee: BASE_FEE,
      networkPassphrase: this.cfg.networkPassphrase,
    })
      .addOperation(new Contract(contractId).call(method, ...args))
      .setTimeout(180)
      .build();

    const sim = await this.server.simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim)) {
      throw new Error(`simulate ${method} failed: ${sim.error}`);
    }
    const assembled = rpc.assembleTransaction(tx, sim).build();

    const signedXdr = await signer.sign(assembled.toXDR());
    const signedTx = TransactionBuilder.fromXDR(signedXdr, this.cfg.networkPassphrase);

    const send = await this.server.sendTransaction(signedTx);
    if (send.status === "ERROR") {
      throw new Error(`send ${method} rejected: ${JSON.stringify(send.errorResult)}`);
    }

    for (let i = 0; i < MAX_POLL_ATTEMPTS; i++) {
      await sleep(POLL_INTERVAL_MS);
      const res = await this.server.getTransaction(send.hash);
      if (res.status === rpc.Api.GetTransactionStatus.NOT_FOUND) continue;
      if (res.status === rpc.Api.GetTransactionStatus.FAILED) {
        throw new Error(`${method} failed on-chain (tx ${send.hash})`);
      }
      return { hash: send.hash, status: res.status, returnValue: res.returnValue };
    }
    throw new Error(`${method} confirmation timed out (tx ${send.hash})`);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Decode the `ConfidentialAccount` struct returned by `confidential_balance`.
 *
 * The keys are the contract's struct field names verbatim (`storage.rs`), so
 * they move when the contract renames them — as `spending_key`/`spendable_balance`/
 * `receiving_balance` did, becoming `spending_public_key`/
 * `spendable_commitment`/`receiving_commitment`. The completeness check at the
 * end is what makes such a rename loud: without it an unrecognized key set
 * yields an all-`undefined` object that passes as a registered account and only
 * fails much later, inside commitment arithmetic.
 */
function parseAccount(val: xdr.ScVal): OnChainAccount {
  const entries = val.map();
  if (!entries) throw new Error("expected ScMap for ConfidentialAccount");
  const out: Partial<OnChainAccount> = {};
  for (const e of entries) {
    const key = e.key().sym().toString();
    switch (key) {
      case "spending_public_key":
        out.spendingKey = pointFromBytes(new Uint8Array(e.val().bytes()));
        break;
      case "viewing_public_key":
        out.viewingPublicKey = pointFromBytes(new Uint8Array(e.val().bytes()));
        break;
      case "spendable_commitment":
        out.spendableBalance = pointFromBytes(new Uint8Array(e.val().bytes()));
        break;
      case "receiving_commitment":
        out.receivingBalance = pointFromBytes(new Uint8Array(e.val().bytes()));
        break;
      case "auditor_id":
        out.auditorId = e.val().u32();
        break;
    }
  }
  const missing = (
    ["spendingKey", "viewingPublicKey", "spendableBalance", "receivingBalance", "auditorId"] as const
  ).filter((k) => out[k] === undefined);
  if (missing.length > 0) {
    throw new Error(
      `ConfidentialAccount is missing ${missing.join(", ")} — the contract's field names ` +
        `(${entries.map((e) => e.key().sym().toString()).join(", ")}) do not match this SDK build`,
    );
  }
  return out as OnChainAccount;
}

/**
 * Decode the `SpenderDelegation` struct returned by `get_spender_delegation`.
 * Field names are the contract's verbatim (`storage.rs`); a missing one throws
 * for the same reason as in {@link parseAccount}.
 */
export function parseDelegation(val: xdr.ScVal): OnChainDelegation {
  const entries = val.map();
  if (!entries) throw new Error("expected ScMap for SpenderDelegation");
  const out: Partial<OnChainDelegation> = {};
  const bytes = (e: xdr.ScMapEntry): Uint8Array => new Uint8Array(e.val().bytes());
  for (const e of entries) {
    switch (e.key().sym().toString()) {
      case "allowance_commitment":
        out.allowanceCommitment = pointFromBytes(bytes(e));
        break;
      case "a_tilde":
        out.aTilde = fromBytesBE(bytes(e));
        break;
      case "escrowed_dvk": {
        const b = bytes(e);
        if (b.length !== 64) throw new Error(`escrowed_dvk: expected 64 bytes, got ${b.length}`);
        out.escrowedDvk = { rX: fromBytesBE(b.subarray(0, 32)), cipher: fromBytesBE(b.subarray(32, 64)) };
        break;
      }
      case "allowance_salt":
        out.allowanceSalt = fromBytesBE(bytes(e));
        break;
      case "live_until_ledger":
        out.liveUntilLedger = e.val().u32();
        break;
    }
  }
  const missing = (
    ["allowanceCommitment", "aTilde", "escrowedDvk", "allowanceSalt", "liveUntilLedger"] as const
  ).filter((k) => out[k] === undefined);
  if (missing.length > 0) {
    throw new Error(
      `SpenderDelegation is missing ${missing.join(", ")} — the contract's field names ` +
        `(${entries.map((e) => e.key().sym().toString()).join(", ")}) do not match this SDK build`,
    );
  }
  return out as OnChainDelegation;
}
