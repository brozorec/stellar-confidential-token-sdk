use std::embedded_curve_ops::EmbeddedCurvePoint;
use stellar_confidential_lib::{
    H, assert_on_curve_non_identity, ecdh, encrypt_amount, poseidon_with_domain, scalar_mul,
    vk_from_sk,
};

mod tests;

// D-sender disclosure circuit -- stellar-confidential
// docs/selective-disclosure/circuits/d-sender.md.
//
// The party that ORIGINATED an on-chain confidential transfer proves, to a
// designated disclosure recipient (P_R, nu), that they paid exactly v_tx to
// the on-chain `to` address recorded in the event. The sender has no ECDH
// path through their own vk into the event ciphertext v_tilde (it is keyed
// to the recipient's PVK_B), so the necessary witness is the transfer's
// ephemeral scalar r_e. The wallet recomputes it off-circuit as
// Poseidon2(delta_eph, vk, sigma_E); this circuit never absorbs delta_eph, it
// only pins r_e through DS3.
//
// Verified entirely OFF-chain, same transport and verifier protocol as
// disclose_recipient. The verifier resolves PVK_A from the account at the
// event's `from` (`spender` for a SpenderTransfer) and PVK_B from the account
// at the event's `to` -- never from the bundle.
//
// Constraints
// -----------
//   D1   vk_A = Poseidon2(delta_vk, sk_A, addr_f)    Contract-bound viewing
//                                                    key.
//   D2   PVK_A = vk_A * H                            Binds proof to the
//                                                    originating account.
//   DS3  R_e = r_e * H, r_e != 0                     Prover knows the
//                                                    transfer's ephemeral
//                                                    scalar (T6 / O6).
//   DS4  s_B = ECDH(r_e, PVK_B)                      Sender-side ECDH to the
//                                                    transfer's recipient.
//   DS5  v_tx = v_tilde
//          - Poseidon2(delta_transfer_amount, s_B, sigma_E)
//                                                    Recipient-side
//                                                    decryption rebuilt from
//                                                    the originator's
//                                                    witnesses (T9).
//   D5   v_tx in [0, 2^127)                          Range validity.
//   U1   R_disc = r_disc * H, r_disc != 0            Disclosure ephemeral key.
//   U2   s_disc = ECDH(r_disc, P_R)                  Disclosure ECDH.
//   U3   v_tilde_disc = v_tx
//          + Poseidon2(delta_disc, s_disc, nu)       Value sealed to the
//                                                    disclosure recipient.
//
// DS3 anchors R_e to the originator: combined with D1/D2 it proves the
// prover is the same party that produced the transfer's ephemeral key.
//
// PVK_B and P_R are public-input points consumed by ECDH with no on-chain
// verifier reconstructing them from trusted storage, so both are checked
// on-curve and non-identity. R_e is bound to an in-circuit scalar_mul output
// (DS3), so unlike disclose_recipient it needs no explicit check.
//
// Every scalar_mul / ecdh goes through the library's witness-base wrappers, so
// no MULTI_SCALAR_MUL here takes the constant H as its base: without --zk,
// bb's fixed-base lookup tables would commit which rows sk / vk / r_e /
// r_disc hit (circuits/scripts/check_witness_lookups.sh upstream).
//
// Public inputs (15 fields, in order)
// -----------------------------------
//   Idx  Param          Symbol         Verifier source
//   ---  -----          ------         ------------------------------------
//   0    addr_f         addr_f         Recomputed from the token contract
//                                      address.
//   1    pvk_a_x        PVK_A.x        `confidential_balance(E.from)`
//   2    pvk_a_y        PVK_A.y         .viewing_public_key (the ORIGINATOR).
//   3    r_e_x          R_e.x          The on-chain event resolved from
//   4    r_e_y          R_e.y           ref_E.
//   5    sigma          sigma_E        Event ECDH nonce.
//   6    v_tilde        v_tilde        Event encrypted amount.
//   7    pvk_b_x        PVK_B.x        `confidential_balance(E.to)`
//   8    pvk_b_y        PVK_B.y         .viewing_public_key (the recipient).
//   9    p_r_x          P_R.x          The verifier's own disclosure key.
//   10   p_r_y          P_R.y
//   11   nu             nu             The verifier's own request nonce.
//   12   r_disc_x       R_disc.x       From the bundle (also ciphertext).
//   13   r_disc_y       R_disc.y
//   14   v_tilde_disc   v_tilde_disc   From the bundle (ciphertext).
//
// Private witnesses
// -----------------
//   sk      Originator's spending secret scalar.
//   r_e     The transfer's ephemeral scalar; r_e != 0 (DS3).
//   v_tx    Plaintext transfer amount.
//   r_disc  Ephemeral scalar for the disclosure ciphertext; r_disc != 0 (U1).

/// Disclosure ciphertext domain tag (`delta_disc`) -- same value as
/// disclose_recipient's; the U-block is shared across the circuit family.
pub global DISCLOSURE: Field = 16;

fn main(
    sk: Field,
    r_e: Field,
    v_tx: Field,
    r_disc: Field,
    addr_f: pub Field,
    pvk_a_x: pub Field,
    pvk_a_y: pub Field,
    r_e_x: pub Field,
    r_e_y: pub Field,
    sigma: pub Field,
    v_tilde: pub Field,
    pvk_b_x: pub Field,
    pvk_b_y: pub Field,
    p_r_x: pub Field,
    p_r_y: pub Field,
    nu: pub Field,
    r_disc_x: pub Field,
    r_disc_y: pub Field,
    v_tilde_disc: pub Field,
) {
    // Degenerate-scalar rejections first (same doctrine as transfer's T13).
    assert(r_e != 0);
    assert(r_disc != 0);

    // D1
    let vk = vk_from_sk(sk, addr_f);

    // D2
    let pvk_derived = scalar_mul(vk, H);
    assert(pvk_derived.x == pvk_a_x);
    assert(pvk_derived.y == pvk_a_y);

    // DS3 -- the originator binding: only the party that sampled r_e at
    // transfer time can satisfy this against the event's emitted R_e.
    let r_e_derived = scalar_mul(r_e, H);
    assert(r_e_derived.x == r_e_x);
    assert(r_e_derived.y == r_e_y);

    // PVK_B is an account-sourced public-input point consumed by ECDH: validate.
    let pvk_b = EmbeddedCurvePoint { x: pvk_b_x, y: pvk_b_y, is_infinite: false };
    assert_on_curve_non_identity(pvk_b);

    // DS4
    let s_b = ecdh(r_e, pvk_b);

    // DS5 -- same algebra as T9, recomputed from the sender side.
    let v_tilde_derived = encrypt_amount(v_tx, s_b, sigma);
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
    // same full-point binding as DS4: `s = Poseidon2(ECDH_SHARED_SECRET, S.x, S.y)`.
    // Taking `S_disc.x` alone would let `P_R` and `-P_R` produce one mask.
    let s_disc = ecdh(r_disc, p_r);

    // U3
    let mask = poseidon_with_domain(DISCLOSURE, [s_disc, nu]);
    assert(v_tx + mask == v_tilde_disc);
}
