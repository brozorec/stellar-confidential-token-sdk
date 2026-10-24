/**
 * High-level submitters for each confidential-token entry point. Each combines
 * the witness payload, the proof bytes, and the plain method arguments into a
 * single `ChainClient.invoke`.
 *
 * Amounts are method arguments (`i128`), not part of the proof payload; the
 * proof binds the confidential debit/credit to the same value.
 */

import { xdr, Address, nativeToScVal } from "@stellar/stellar-sdk";

import type { ChainClient, Signer, InvokeResult } from "./client.js";
import {
  encodeRegisterData,
  encodeWithdrawData,
  encodeTransferData,
  encodeSetSpenderData,
  encodeSpenderTransferData,
} from "./payload.js";
import type { RegisterWitness } from "../witness/register.js";
import type { WithdrawWitness } from "../witness/withdraw.js";
import type { TransferWitness } from "../witness/transfer.js";
import type { SetSpenderWitness } from "../witness/set-spender.js";
import type { SpenderTransferWitness } from "../witness/spender-transfer.js";

const addr = (a: string): xdr.ScVal => new Address(a).toScVal();
const i128 = (v: bigint): xdr.ScVal => nativeToScVal(v, { type: "i128" });

/** `register(account, auditor_id, data)`. */
export function submitRegister(
  client: ChainClient,
  signer: Signer,
  account: string,
  auditorId: number,
  witness: RegisterWitness,
  proof: Uint8Array,
): Promise<InvokeResult> {
  return client.invoke(
    client.cfg.contracts.token,
    "register",
    [addr(account), xdr.ScVal.scvU32(auditorId), encodeRegisterData(witness, proof)],
    signer,
  );
}

/** `deposit(from, to, amount)` — public → confidential, no proof. */
export function submitDeposit(
  client: ChainClient,
  signer: Signer,
  from: string,
  to: string,
  amount: bigint,
): Promise<InvokeResult> {
  return client.invoke(
    client.cfg.contracts.token,
    "deposit",
    [addr(from), addr(to), i128(amount)],
    signer,
  );
}

/** `merge(account)` — fold receiving balance into spendable, no proof. */
export function submitMerge(
  client: ChainClient,
  signer: Signer,
  account: string,
): Promise<InvokeResult> {
  return client.invoke(client.cfg.contracts.token, "merge", [addr(account)], signer);
}

/** `withdraw(from, to, amount, data)` — confidential → public. */
export function submitWithdraw(
  client: ChainClient,
  signer: Signer,
  from: string,
  to: string,
  amount: bigint,
  witness: WithdrawWitness,
  proof: Uint8Array,
): Promise<InvokeResult> {
  return client.invoke(
    client.cfg.contracts.token,
    "withdraw",
    [addr(from), addr(to), i128(amount), encodeWithdrawData(witness, proof)],
    signer,
  );
}

/** `confidential_transfer(from, to, data)` — confidential → confidential. */
export function submitTransfer(
  client: ChainClient,
  signer: Signer,
  from: string,
  to: string,
  witness: TransferWitness,
  proof: Uint8Array,
): Promise<InvokeResult> {
  return client.invoke(
    client.cfg.contracts.token,
    "confidential_transfer",
    [addr(from), addr(to), encodeTransferData(witness, proof)],
    signer,
  );
}

/**
 * `set_spender(account, spender, live_until_ledger, data)` — escrow an
 * allowance to a registered `spender`, spendable while
 * `ledger ≤ liveUntilLedger`. Reverts with `DelegationAlreadyExists` (3503)
 * while any entry for the pair exists, expired or not: revoke first.
 *
 * The contract stores any `live_until_ledger`, even a past one, and the escrow
 * then sits unspendable until revoked. So this refuses one that is not after
 * `latestLedger() + 1`. The entry lands at `latestLedger() + 1` at the
 * earliest, and a spender reading it there already sees it expired
 * (`delegationStatus`).
 *
 * @throws {Error} if `liveUntilLedger ≤ latestLedger() + 1`; nothing is
 *   submitted.
 */
export async function submitSetSpender(
  client: ChainClient,
  signer: Signer,
  account: string,
  spender: string,
  liveUntilLedger: number,
  witness: SetSpenderWitness,
  proof: Uint8Array,
): Promise<InvokeResult> {
  const latest = await client.latestLedger();
  if (liveUntilLedger <= latest + 1) {
    throw new Error(
      `set_spender: liveUntilLedger ${liveUntilLedger} leaves no ledger to spend in ` +
        `(latest ledger ${latest}; the delegation lands at ${latest + 1} at the earliest)`,
    );
  }
  return client.invoke(
    client.cfg.contracts.token,
    "set_spender",
    [addr(account), addr(spender), xdr.ScVal.scvU32(liveUntilLedger), encodeSetSpenderData(witness, proof)],
    signer,
  );
}

/**
 * `confidential_transfer_from(spender, from, to, data)` — the spender pays
 * `to` out of `from`'s allowance. Only `spender` authorizes.
 */
export function submitSpenderTransfer(
  client: ChainClient,
  signer: Signer,
  spender: string,
  from: string,
  to: string,
  witness: SpenderTransferWitness,
  proof: Uint8Array,
): Promise<InvokeResult> {
  return client.invoke(
    client.cfg.contracts.token,
    "confidential_transfer_from",
    [addr(spender), addr(from), addr(to), encodeSpenderTransferData(witness, proof)],
    signer,
  );
}

/**
 * `revoke_spender(account, spender)` — fold the remaining allowance back into
 * `account`'s spendable balance and delete the delegation, live or expired.
 * No proof.
 */
export function submitRevokeSpender(
  client: ChainClient,
  signer: Signer,
  account: string,
  spender: string,
): Promise<InvokeResult> {
  return client.invoke(client.cfg.contracts.token, "revoke_spender", [addr(account), addr(spender)], signer);
}
