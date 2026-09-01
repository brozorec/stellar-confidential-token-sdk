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
import { encodeRegisterData, encodeWithdrawData, encodeTransferData } from "./payload.js";
import type { RegisterWitness } from "../witness/register.js";
import type { WithdrawWitness } from "../witness/withdraw.js";
import type { TransferWitness } from "../witness/transfer.js";

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
