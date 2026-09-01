/**
 * Local confidential-state types. The protocol keeps only Pedersen commitments
 * on-chain; the *openings* (`v`, `r`) live only in events and must be cached
 * locally to remain spendable. See `engine.ts` for the reconstruction rules and
 * the retention caveat.
 */

/** A Pedersen commitment opening: `C = v·G + r·H`. */
export interface Opening {
  /** Plaintext value (an amount for balances). */
  v: bigint;
  /** Blinding factor (field element). */
  r: bigint;
}

/** Reconstructed local state for one confidential account. */
export interface AccountState {
  /** Owner's Stellar (G-) address. */
  address: string;
  /** Spendable balance opening (`C_spend`). */
  spendable: Opening;
  /** Receiving balance opening (`C_receive`). */
  receiving: Opening;
  /** Whether a register event has been observed for this address. */
  registered: boolean;
  /** RPC paging cursor to resume the next sync from. */
  cursor?: string;
  /** Highest ledger reflected in this state. */
  syncedLedger: number;
}

export function freshState(address: string): AccountState {
  return {
    address,
    spendable: { v: 0n, r: 0n },
    receiving: { v: 0n, r: 0n },
    registered: false,
    syncedLedger: 0,
  };
}
