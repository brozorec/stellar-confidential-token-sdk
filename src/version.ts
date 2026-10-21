/**
 * Version matrix (stellar-confidential
 * docs/sdk/requirements.md#non-functional-requirements): the values a bug
 * report needs to diagnose an interoperability mismatch. Each is a boundary
 * whose mismatch fails silently or as a bare on-chain rejection — a VK set
 * from another release, a toolchain that derives different keys, a different
 * domain-separator scheme.
 *
 * `test/artifacts.mjs` pins these against `circuits/manifest.json` and
 * `package.json`, so a re-vendor or a version bump cannot leave them stale.
 */

import { addressToField } from "./crypto/address.js";
import { toHex32 } from "./crypto/field.js";

export const VERSIONS = {
  /** This package. */
  sdk: "0.2.0",
  /** The protocol release (and its documentation set) the SDK implements. */
  protocol: {
    crate: "stellar-confidential",
    version: "0.8.0",
    repository: "https://github.com/OpenZeppelin/stellar-contracts",
    tag: "v0.8.0",
    commit: "ddc327eb92d63709436da3a8455f641c2d5476c5",
    docs: "packages/confidential/docs",
  },
  /** Producing toolchain of the circuits and VKs, and the proving stack. */
  toolchain: {
    nargo: "1.0.0-beta.11",
    bb: "0.87.0",
    bbJs: "0.87.0",
    noirJs: "1.0.0-beta.11",
    onChainVerifier: "ultrahonk_soroban_verifier 0.1.0",
  },
  /**
   * sha256 of every verification key the SDK's proofs target, keyed by path
   * under `circuits/`. `vks/` are the on-chain VKs (non-ZK); `disclosure/` are
   * the pinned off-chain disclosure VKs (ZK).
   */
  verificationKeys: {
    "vks/register.vk.bin": "f994f89b761fac6905926971ab43a60928e39449dbabe934c32d3e13540c3f51",
    "vks/withdraw.vk.bin": "9af904154ad8a92861cb2064e499d777ef571a3144636f549263fe8f5a28af74",
    "vks/transfer.vk.bin": "cd77164631a37072d9ef85413b63f12dbaf7720a7c9069afc07277b02932b963",
    "vks/set_spender.vk.bin": "8e5fc7db817e6ba1a536f9b1f98bc75e64ce14e35f636d7f05ca22ed7a8fd656",
    "vks/spender_transfer.vk.bin": "c979e925ba265e207dd0de919dc29577e270bf7f75340a487e0d1b6396394ddc",
    "vks/clawback.vk.bin": "665eb9cf680c89228084647b0d601183f44678c259ed400bd08226024310560b",
    "disclosure/disclose_recipient.vk.json": "29de28233e88bf1a405a816580b58c052147447d8f4943288819bb7200d3d410",
    "disclosure/disclose_sender.vk.json": "388190c49d458af0c86f857e4d7390690f431c6ec28de262a82165c8e4e991b9",
  },
  /**
   * The sequential `1..17` assignment of docs/protocol/domain-separators.md,
   * not its alternate hashed scheme (`DOMAIN` in `crypto/constants.ts`).
   */
  domainSeparators: "sequential",
} as const;

export interface VersionMatrix {
  versions: typeof VERSIONS;
  /** The deployment the client talks to, when known. */
  deployment: { contract: string; addrF: string } | null;
}

/** The full matrix, including the deployment's `addr_f` when `token` is given. */
export function versionMatrix(token?: string): VersionMatrix {
  return {
    versions: VERSIONS,
    deployment: token ? { contract: token, addrF: toHex32(addressToField(token)) } : null,
  };
}
