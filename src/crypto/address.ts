/**
 * `address_to_field` — Poseidon2 compression of a Stellar strkey into one
 * `F_r` element, matching `storage.rs::address_to_field`.
 *
 * The contract takes the 56-character strkey ASCII (`C…` for contracts, `G…`
 * for accounts), splits it into two 28-byte limbs, interprets each
 * little-endian as a field element, and hashes `Poseidon2(ADDRESS, lo, hi)`.
 *
 * This value is the domain separator baked into every account's viewing key
 * (`vk = Poseidon2(VIEWING_KEY, sk, addr_f)`), so it MUST equal the
 * contract's stored `AddressAsField`. Deployment tooling asserts that equality
 * against the on-chain value as a guard against any Poseidon2 drift.
 */

import { DOMAIN } from "./constants.js";
import { fromBytesLE } from "./field.js";
import { poseidonWithDomain } from "./poseidon2.js";

const STRKEY_LEN = 56;
const STRKEY_LIMB_LEN = 28;

/**
 * @param strkey - The Stellar strkey string (e.g. a `C…` contract address).
 */
export function addressToField(strkey: string): bigint {
  const ascii = new TextEncoder().encode(strkey);
  if (ascii.length !== STRKEY_LEN) {
    throw new Error(
      `address_to_field expects a ${STRKEY_LEN}-char strkey, got ${ascii.length}: ${strkey}`,
    );
  }
  const lo = fromBytesLE(ascii.subarray(0, STRKEY_LIMB_LEN));
  const hi = fromBytesLE(ascii.subarray(STRKEY_LIMB_LEN, STRKEY_LEN));
  return poseidonWithDomain(DOMAIN.ADDRESS, [lo, hi]);
}
