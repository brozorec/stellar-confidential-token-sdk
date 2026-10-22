use std::embedded_curve_ops::EmbeddedCurvePoint;
use stellar_confidential_lib::{
    H, assert_on_curve_non_identity, ecdh, encrypt_amount, poseidon_with_domain, scalar_mul,
    vk_from_sk,
};

mod tests;

// D-recipient disclosure circuit -- stellar-confidential
// docs/selective-disclosure/circuits/d-recipient.md.
//
// The holder of the account that *received* an on-chain confidential transfer
// proves, to a designated disclosure recipient (P_R, nu), that the transfer
// event (R_e, sigma_E, v_tilde) paid them exactly v_tx -- without revealing
// sk, vk, or anything else. The disclosed value travels only inside the
// recipient-bound ciphertext (R_disc, v_tilde_disc), so the proof itself can
// be archived in the clear.
//
// Verified entirely OFF-chain by bb.js (docs/selective-disclosure/protocol.md
// #verifier-protocol); it is not registered with the on-chain verifier. The
// verifier MUST source every public input except (R_disc, v_tilde_disc) from
// on-chain state resolved via ref_E -- never from the prover's bundle.
//
// Constraints
// -----------
//   D1  vk_A = Poseidon2(delta_vk, sk_A, addr_f)     Contract-bound viewing
//                                                    key (mirrors T2).
//   D2  PVK_A = vk_A * H                             Binds proof to the
//                                                    on-chain account record
//                                                    at the event's `to`.
//   D3  s = ECDH(vk_A, R_e)                          Recipient-side ECDH.
//   D4  v_tx = v_tilde
//          - Poseidon2(delta_transfer_amount, s, sigma_E)
//                                                    Correct decryption of
//                                                    the event amount (T9/O9).
//   D5  v_tx in [0, 2^127)                           Range validity.
//   U1  R_disc = r_disc * H, r_disc != 0             Disclosure ephemeral key.
//   U2  s_disc = ECDH(r_disc, P_R)                   Disclosure ECDH.
//   U3  v_tilde_disc = v_tx
//          + Poseidon2(delta_disc, s_disc, nu)       Value sealed to the
//                                                    disclosure recipient,
//                                                    bound to their nonce.
//
// sigma_E is sigma for a Transfer event and sigma_a' for a SpenderTransfer;
// the constraint shape is identical, so one circuit serves both.
//
// R_e and P_R are public-input points consumed by ECDH that no on-chain
// verifier reconstructs from trusted storage (R_e comes from an event, P_R is
// the recipient's own key), so both are checked on-curve and non-identity.
// PVK_A and R_disc are only *compared* against in-circuit scalar_mul outputs,
// which are on-curve by construction.
//
// Every scalar_mul / ecdh goes through the library's witness-base wrappers, so
// no MULTI_SCALAR_MUL here takes the constant H as its base: without --zk,
// bb's fixed-base lookup tables would commit which rows sk / vk / r_disc hit
// (circuits/scripts/check_witness_lookups.sh upstream).
//
// Public inputs (13 fields, in order)
// -----------------------------------
//   Idx  Param          Symbol         Verifier source
//   ---  -----          ------         ------------------------------------
//   0    addr_f         addr_f         Recomputed from the token contract
//                                      address.
//   1    pvk_a_x        PVK_A.x        `confidential_balance(E.to)`
//   2    pvk_a_y        PVK_A.y         .viewing_public_key.
//   3    r_e_x          R_e.x          The on-chain event resolved from
//   4    r_e_y          R_e.y           ref_E.
//   5    sigma          sigma_E        Event ECDH nonce.
//   6    v_tilde        v_tilde        Event encrypted amount.
//   7    p_r_x          P_R.x          The verifier's own disclosure key.
//   8    p_r_y          P_R.y
//   9    nu             nu             The verifier's own request nonce.
//   10   r_disc_x       R_disc.x       From the bundle (also ciphertext).
//   11   r_disc_y       R_disc.y
//   12   v_tilde_disc   v_tilde_disc   From the bundle (ciphertext).
//
// Private witnesses
// -----------------
//   sk      Holder's spending secret scalar.
//   v_tx    Plaintext transfer amount (decrypted from the event).
//   r_disc  Ephemeral scalar for the disclosure ciphertext; r_disc != 0 (U1).

/// Disclosure ciphertext domain tag (`delta_disc`,
/// docs/protocol/domain-separators.md). The core library leaves 14-16
/// unimplemented, so it is defined here; the SDK's `DOMAIN.DISCLOSURE` must
/// match. 16 and not 13: the library's `ecdh` absorbs 13, so sharing it would
/// put the U3 pad and every ECDH extraction in this circuit on one domain.
pub global DISCLOSURE: Field = 16;

fn main(
    sk: Field,
    v_tx: Field,
    r_disc: Field,
    addr_f: pub Field,
    pvk_a_x: pub Field,
    pvk_a_y: pub Field,
    r_e_x: pub Field,
    r_e_y: pub Field,
    sigma: pub Field,
    v_tilde: pub Field,
    p_r_x: pub Field,
    p_r_y: pub Field,
    nu: pub Field,
    r_disc_x: pub Field,
    r_disc_y: pub Field,
    v_tilde_disc: pub Field,
) {
    // U1 (scalar part) -- runs first so a degenerate r_disc is rejected
    // before any scalar mul against it (same doctrine as transfer's T13).
    assert(r_disc != 0);

    // D1
    let vk = vk_from_sk(sk, addr_f);

    // D2
    let pvk_derived = scalar_mul(vk, H);
    assert(pvk_derived.x == pvk_a_x);
    assert(pvk_derived.y == pvk_a_y);

    // R_e is an event-sourced public-input point consumed by ECDH: validate.
    let r_e = EmbeddedCurvePoint { x: r_e_x, y: r_e_y, is_infinite: false };
    assert_on_curve_non_identity(r_e);

    // D3
    let s = ecdh(vk, r_e);

    // D4 -- same algebra as T9, recomputed from the recipient side.
    let v_tilde_derived = encrypt_amount(v_tx, s, sigma);
    assert(v_tilde_derived == v_tilde);

    // D5
    v_tx.assert_max_bit_size::<127>();

    // U1 (point part)
    let r_disc_derived = scalar_mul(r_disc, H);
    assert(r_disc_derived.x == r_disc_x);
    assert(r_disc_derived.y == r_disc_y);

    // P_R is the disclosure recipient's key, consumed by ECDH: validate.
    let p_r = EmbeddedCurvePoint { x: p_r_x, y: p_r_y, is_infinite: false };
    assert_on_curve_non_identity(p_r);

    // U2 -- via the shared `ecdh` gadget, so the disclosure channel inherits the
    // same full-point binding as D3: `s = Poseidon2(ECDH_SHARED_SECRET, S.x, S.y)`.
    // Taking `S_disc.x` alone would let `P_R` and `-P_R` produce one mask.
    let s_disc = ecdh(r_disc, p_r);

    // U3
    let mask = poseidon_with_domain(DISCLOSURE, [s_disc, nu]);
    assert(v_tx + mask == v_tilde_disc);
}
