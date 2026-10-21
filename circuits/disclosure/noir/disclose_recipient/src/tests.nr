use crate::{DISCLOSURE, main};
use stellar_confidential_lib::{
    H, ecdh, encrypt_amount, poseidon_with_domain, scalar_mul, vk_from_sk,
};

// Self-contained fixture: every public input is derived in-test from the
// secrets below via the same lib primitives the circuit constrains, so the
// happy path doubles as a sender/recipient ECDH symmetry check
// (ecdh(vk, r_e*H) == ecdh(r_e, vk*H)).
global SK: Field = 0xdead;
global ADDR_F: Field = 0xbeef;
global R_E: Field = 0x1234; // sender's ephemeral scalar
global SIGMA: Field = 0x5678;
global V_TX: Field = 250;
global R_DISC: Field = 0x9abc;
global R_R: Field = 0xfeed; // disclosure recipient's secret key
global NU: Field = 0x4242;

struct Fixture {
    pvk_x: Field,
    pvk_y: Field,
    r_e_x: Field,
    r_e_y: Field,
    v_tilde: Field,
    p_r_x: Field,
    p_r_y: Field,
    r_disc_x: Field,
    r_disc_y: Field,
    v_tilde_disc: Field,
}

fn seal(v_tx: Field) -> Field {
    let p_r = scalar_mul(R_R, H);
    v_tx + poseidon_with_domain(DISCLOSURE, [ecdh(R_DISC, p_r), NU])
}

fn fixture() -> Fixture {
    let vk = vk_from_sk(SK, ADDR_F);
    let pvk = scalar_mul(vk, H);
    let r_e_point = scalar_mul(R_E, H);
    // Sender-side derivation of the event ciphertext (transfer's T5/T9).
    let v_tilde = encrypt_amount(V_TX, ecdh(R_E, pvk), SIGMA);

    let p_r = scalar_mul(R_R, H);
    let r_disc_point = scalar_mul(R_DISC, H);

    Fixture {
        pvk_x: pvk.x,
        pvk_y: pvk.y,
        r_e_x: r_e_point.x,
        r_e_y: r_e_point.y,
        v_tilde,
        p_r_x: p_r.x,
        p_r_y: p_r.y,
        r_disc_x: r_disc_point.x,
        r_disc_y: r_disc_point.y,
        v_tilde_disc: seal(V_TX),
    }
}

fn run(f: Fixture, sk: Field, v_tx: Field, sigma: Field, nu: Field) {
    main(
        sk,
        v_tx,
        R_DISC,
        ADDR_F,
        f.pvk_x,
        f.pvk_y,
        f.r_e_x,
        f.r_e_y,
        sigma,
        f.v_tilde,
        f.p_r_x,
        f.p_r_y,
        nu,
        f.r_disc_x,
        f.r_disc_y,
        f.v_tilde_disc,
    );
}

#[test]
fn discloses_event_amount() {
    run(fixture(), SK, V_TX, SIGMA, NU);
}

#[test(should_fail)]
fn rejects_wrong_amount() {
    // v_tx + 1 breaks D4 (the event ciphertext decrypts to V_TX, not V_TX+1).
    run(fixture(), SK, V_TX + 1, SIGMA, NU);
}

#[test(should_fail)]
fn rejects_wrong_sk() {
    // A different sk derives a different vk, so D2 (PVK binding) fails.
    run(fixture(), SK + 1, V_TX, SIGMA, NU);
}

#[test(should_fail)]
fn rejects_wrong_sigma() {
    // sigma is bound into the D4 decryption mask.
    run(fixture(), SK, V_TX, SIGMA + 1, NU);
}

#[test(should_fail)]
fn rejects_wrong_nonce() {
    // A replay against a different request nonce breaks U3.
    run(fixture(), SK, V_TX, SIGMA, NU + 1);
}

#[test(should_fail)]
fn rejects_tampered_disclosure_ciphertext() {
    let mut f = fixture();
    // v_tilde_disc - 1 would understate the disclosed amount by one: U3.
    f.v_tilde_disc -= 1;
    run(f, SK, V_TX, SIGMA, NU);
}

#[test(should_fail)]
fn rejects_foreign_event() {
    // Swap in an R_e the holder has no ECDH relation to (a different
    // transfer's ephemeral key): D4 decrypts to a different value.
    let mut f = fixture();
    let other = scalar_mul(R_E + 1, H);
    f.r_e_x = other.x;
    f.r_e_y = other.y;
    run(f, SK, V_TX, SIGMA, NU);
}

#[test(should_fail)]
fn rejects_negated_event_key() {
    // -R_e shares R_e's x-coordinate. The ECDH extraction absorbs S.y, so the
    // negated key yields a different shared secret and D4 fails.
    let mut f = fixture();
    f.r_e_y = 0 - f.r_e_y;
    run(f, SK, V_TX, SIGMA, NU);
}

#[test(should_fail)]
fn rejects_identity_disclosure_key() {
    // P_R = O would make s_disc public for every r_disc.
    let mut f = fixture();
    f.p_r_x = 0;
    f.p_r_y = 0;
    run(f, SK, V_TX, SIGMA, NU);
}

#[test(should_fail)]
fn rejects_out_of_range_amount() {
    // Rebuild a consistent ciphertext for v_tx = 2^127 -- D1..D4 and the
    // U-block all pass; only the D5 range check can reject it.
    let huge: Field = 0x80000000000000000000000000000000;
    let pvk = scalar_mul(vk_from_sk(SK, ADDR_F), H);
    let mut f = fixture();
    f.v_tilde = encrypt_amount(huge, ecdh(R_E, pvk), SIGMA);
    f.v_tilde_disc = seal(huge);
    run(f, SK, huge, SIGMA, NU);
}

#[test]
fn recipient_can_decrypt() {
    // U-block round trip from the disclosure recipient's side: r_R * R_disc
    // recovers the same shared secret, so v_tilde_disc - mask == V_TX.
    let f = fixture();
    let r_disc_point = scalar_mul(R_DISC, H);
    let mask = poseidon_with_domain(DISCLOSURE, [ecdh(R_R, r_disc_point), NU]);
    assert(f.v_tilde_disc - mask == V_TX);
}
