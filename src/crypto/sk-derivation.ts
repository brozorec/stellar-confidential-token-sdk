/**
 * SDK.md §5 — deterministic account-secret derivation.
 *
 * The protocol's recovery guarantee (DESIGN.md §5.2, INDEXER.md §1) rests on
 * `sk` being *derivable*, not stored: given the same root and the same
 * `(contract, account)` pair, every conformant client MUST arrive at the same
 * `sk`, on any device, forever. A client that draws `sk` randomly can never
 * rebuild the account from a seed, whatever history it replays.
 *
 * The chain, verbatim from §5.1:
 *
 *   msg  = "openzeppelin/confidential-token/v1/sk" || 0x0a
 *          || enc(contract) || 0x0a || enc(account)
 *   root = Ed25519-Sign(sk_ed, SHA-256("Stellar Signed Message:\n" || msg))
 *   sk   = RS(HKDF-SHA-512(
 *            IKM  = root,
 *            salt = "openzeppelin/confidential-token/v1/sk",
 *            info = be_32(addr_f) || be_32(acct_f) || le_4(j)))
 *
 * where `RS` is the §4.7 rejection procedure ({@link rejectionSample}) and `j`
 * starts at 0, incrementing on every rejection — both when `RS` rejects the
 * candidate and when the induced `vk` would be zero (register constraint R5
 * forbids a zero `vk`, and `vk` is a function of `sk`).
 *
 * Nothing here is constrained by any circuit (register constrains only
 * `Y = sk·H` and `vk`'s derivation from `sk`), so every constant below is a
 * cross-client wire contract in the same sense as the domain tags: a client
 * that disagrees on any byte derives a different, wrong-but-usable `sk`, and
 * `register` being single-use makes that unrepairable. The §6.3 chain vector
 * (`test/vectors/sk_derivation_chain.json`) pins the whole chain end-to-end.
 *
 * Note the domain string is used TWICE, in two different roles: as the
 * newline-delimited first line of the signed message (§5.2) and as the HKDF
 * salt (§5.1). That is intentional in the spec, not a transcription error.
 *
 * This layer deliberately does not touch a wallet. The caller obtains the
 * root — a SEP-0053 signature over {@link skSigningMessage} (§5.2) or a raw
 * 32-byte value (§5.3) — and hands it in, keeping the derivation pure.
 * Callers with a signer MUST follow §5.2's obligations that live outside this
 * function: verify the signature against the expected ed25519 key, obtain it
 * twice to detect non-deterministic signers, and never persist the root.
 */

import { hkdf } from "@noble/hashes/hkdf";
import { sha256, sha512 } from "@noble/hashes/sha2";

import { addressToField } from "./address.js";
import { rejectionSample, toBytes32BE } from "./field.js";
import { vkFromSk } from "./poseidon2.js";

/**
 * The protocol/deployment domain string, used as the first line of the §5.2
 * signed message AND as the §5.1 HKDF salt.
 */
export const SK_DOMAIN = "openzeppelin/confidential-token/v1/sk";

/** SEP-0053's fixed 24-ASCII-byte signing prefix. */
export const SEP53_PREFIX = "Stellar Signed Message:\n";

/** Newline separating the signed message's three fields. */
const LF = 0x0a;

/**
 * Guard against a runaway derivation. Each rejection has probability < 1/2,
 * so reaching this bound (probability ~2^-64 at worst) means the inputs or
 * the primitives are wrong, and failing loudly beats spinning.
 */
const MAX_REJECTIONS = 64;

/** ASCII-encode, asserting purity (strkeys and the domain string are ASCII). */
function ascii(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0x7f) {
      throw new Error(`expected ASCII, got U+${c.toString(16)} in ${JSON.stringify(s)}`);
    }
    out[i] = c;
  }
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** `le_4(j)` — 4-byte little-endian encoding of the rejection counter. */
export function le4(j: number): Uint8Array {
  if (!Number.isInteger(j) || j < 0 || j > 0xffff_ffff) {
    throw new Error(`le_4 expects a uint32, got ${j}`);
  }
  return new Uint8Array([j & 0xff, (j >>> 8) & 0xff, (j >>> 16) & 0xff, (j >>> 24) & 0xff]);
}

/**
 * The message a §5.2 signer root signs:
 * `SK_DOMAIN || 0x0a || enc(contract) || 0x0a || enc(account)`.
 *
 * Carries the full 56-char strkeys (not their `address_to_field` compressions)
 * so a wallet rendering SEP-0053 messages as text shows the user addresses
 * they can compare against the deployment they intend to register on.
 *
 * @param contract  the confidential-token contract's `C…` strkey.
 * @param account   the `G…` strkey of the address being registered.
 */
export function skSigningMessage(contract: string, account: string): Uint8Array {
  return concatBytes(
    ascii(SK_DOMAIN),
    new Uint8Array([LF]),
    ascii(contract),
    new Uint8Array([LF]),
    ascii(account),
  );
}

/**
 * The SEP-0053 signing payload `SHA-256(prefix || msg)`. This 32-byte digest —
 * not the message — is what ed25519 signs, so a wallet's `signMessage` and a
 * raw `Keypair.sign` agree only if the caller hashes exactly this way.
 */
export function sep53Payload(message: Uint8Array): Uint8Array {
  return sha256(concatBytes(ascii(SEP53_PREFIX), message));
}

/** Convenience: the exact 32 bytes to sign for a `(contract, account)` pair. */
export function skSigningPayload(contract: string, account: string): Uint8Array {
  return sep53Payload(skSigningMessage(contract, account));
}

export interface DerivedSecret {
  /** The account secret `sk`, a nonzero element of `[1, r)`. */
  sk: bigint;
  /** The induced viewing key `vk = Poseidon2(VIEWING_KEY, sk, addr_f)`. */
  vk: bigint;
  /**
   * How many rejections occurred (0 in the overwhelming majority of cases).
   * An OUTPUT of the derivation, not an input: a client that samples
   * candidates differently lands on a different `j` and a different `sk`.
   */
  j: number;
}

/**
 * Derive `sk` (and the `vk` it implies) from a root, per §5.1.
 *
 * @param root   the root's bytes verbatim — a 64-byte ed25519 SEP-0053
 *               signature (§5.2) or a raw 32-byte value (§5.3). The IKM is
 *               these bytes as-is; HKDF accepts any length, so only emptiness
 *               is rejected here.
 * @param addrF  `address_to_field(contract)`.
 * @param acctF  `address_to_field(account)` of the address being registered.
 *               Folding it in gives each address a distinct `sk`; reusing one
 *               `sk` across addresses would publish identical `Y`/`PVK` under
 *               both, linking them for any observer (§5.1).
 */
export function deriveSkFromRoot(root: Uint8Array, addrF: bigint, acctF: bigint): DerivedSecret {
  if (root.length === 0) throw new Error("§5.1 root must not be empty");

  const salt = ascii(SK_DOMAIN);
  const addrBytes = toBytes32BE(addrF);
  const acctBytes = toBytes32BE(acctF);

  for (let j = 0; j <= MAX_REJECTIONS; j++) {
    const info = concatBytes(addrBytes, acctBytes, le4(j));
    const okm = hkdf(sha512, root, salt, info, 32);
    const sk = rejectionSample(okm);
    if (sk === null) continue;
    const vk = vkFromSk(sk, addrF);
    if (vk === 0n) continue; // register constraint R5: vk must be nonzero
    return { sk, vk, j };
  }

  throw new Error(
    `§5.1 derivation found no acceptable sk in ${MAX_REJECTIONS} attempts; ` +
      "the root or the field parameters are almost certainly wrong",
  );
}

/**
 * Full §5.1 derivation from strkeys: resolves both addresses through
 * `address_to_field` and derives the secret. Feed the result's `sk`/`addrF`
 * to `deriveKeys` for the full key set (`Y`, `PVK`).
 */
export function deriveSk(
  root: Uint8Array,
  contract: string,
  account: string,
): DerivedSecret & { addrF: bigint; acctF: bigint } {
  const addrF = addressToField(contract);
  const acctF = addressToField(account);
  return { ...deriveSkFromRoot(root, addrF, acctF), addrF, acctF };
}
