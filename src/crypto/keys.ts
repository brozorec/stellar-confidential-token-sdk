/**
 * Key derivation. Unlike the previous design, every key is **contract-bound**:
 * the viewing key folds in `addr_f` (the token contract's address-as-field), so
 * a key set generated for one deployment is meaningless against another.
 *
 *   sk  (random F_r scalar, the only secret)
 *    ├─ vk  = Poseidon2(VIEWING_KEY, sk, addr_f)
 *    ├─ Y   = sk · H        (spending public key)
 *    └─ PVK = vk · H        (public viewing key — others' ECDH target for you)
 */

import { H, scalarMul, type Point } from "./grumpkin.js";
import { vkFromSk } from "./poseidon2.js";
import { randomScalar, toHex32 } from "./field.js";

export interface KeyPair {
  /** Secret spending scalar (the root secret). */
  sk: bigint;
  /** Contract-bound viewing key `vk = Poseidon2(VIEWING_KEY, sk, addr_f)`. */
  vk: bigint;
  /** Spending public key `Y = sk · H`. */
  Y: Point;
  /** Public viewing key `PVK = vk · H`. */
  PVK: Point;
  /** The `addr_f` these keys are bound to. */
  addrF: bigint;
}

export interface SerializedKeyPair {
  sk: string;
  addrF: string;
}

/** Derive the full key set for a given secret and contract `addr_f`. */
export function deriveKeys(sk: bigint, addrF: bigint): KeyPair {
  const vk = vkFromSk(sk, addrF);
  const Y = scalarMul(sk, H);
  const PVK = scalarMul(vk, H);
  return { sk, vk, Y, PVK, addrF };
}

/** Generate a fresh key set bound to `addr_f`. */
export function generateKeys(addrF: bigint): KeyPair {
  return deriveKeys(randomScalar(), addrF);
}

/** A key pair is fully determined by `(sk, addr_f)`. */
export function serializeKeys(keys: KeyPair): SerializedKeyPair {
  return { sk: toHex32(keys.sk), addrF: toHex32(keys.addrF) };
}

export function deserializeKeys(data: SerializedKeyPair): KeyPair {
  return deriveKeys(BigInt(data.sk), BigInt(data.addrF));
}
