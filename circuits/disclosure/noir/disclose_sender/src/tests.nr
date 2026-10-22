use crate::{DISCLOSURE, main};
use stellar_confidential_lib::{
    H, ecdh, encrypt_amount, poseidon_with_domain, scalar_mul, vk_from_sk,
};

// Self-contained fixture: SK_A is the sender (originator), SK_B the transfer
// recipient. The event ciphertext is derived sender-side exactly as the
// transfer circuit does (T5/T9); the D-sender circuit must reconstruct it
// from (sk_A, r_e) without any access to sk_B.
global SK_A: Field = 0xdead;
global SK_B: Field = 0xd00d;
global ADDR_F: Field = 0xbeef;
global R_E: Field = 0x1234;
global SIGMA: Field = 0x5678;
global V_TX: Field = 250;
global R_DISC: Field = 0x9abc;
global R_R: Field = 0xfeed; // disclosure recipient's secret key
global NU: Field = 0x4242;

struct Fixture {
    pvk_a_x: Field,
    pvk_a_y: Field,
    r_e_x: Field,
    r_e_y: Field,
    v_tilde: Field,
    pvk_b_x: Field,
    pvk_b_y: Field,
    p_r_x: Field,
    p_r_y: Field,
    r_disc_x: Field,
    r_disc_y: Field,
    v_tilde_disc: Field,
}

fn fixture() -> Fixture {
    let pvk_a = scalar_mul(vk_from_sk(SK_A, ADDR_F), H);
    let pvk_b = scalar_mul(vk_from_sk(SK_B, ADDR_F), H);
    let r_e_point = scalar_mul(R_E, H);
    // Sender-side derivation of the event ciphertext (transfer's T5/T9):
    // keyed to the RECIPIENT's PVK_B.
    let v_tilde = encrypt_amount(V_TX, ecdh(R_E, pvk_b), SIGMA);

    let p_r = scalar_mul(R_R, H);
    let r_disc_point = scalar_mul(R_DISC, H);
    let v_tilde_disc = V_TX + poseidon_with_domain(DISCLOSURE, [ecdh(R_DISC, p_r), NU]);

    Fixture {
        pvk_a_x: pvk_a.x,
        pvk_a_y: pvk_a.y,
        r_e_x: r_e_point.x,
        r_e_y: r_e_point.y,
        v_tilde,
        pvk_b_x: pvk_b.x,
        pvk_b_y: pvk_b.y,
        p_r_x: p_r.x,
        p_r_y: p_r.y,
        r_disc_x: r_disc_point.x,
        r_disc_y: r_disc_point.y,
        v_tilde_disc,
    }
}

fn run(f: Fixture, sk: Field, r_e: Field, v_tx: Field, nu: Field) {
    main(
        sk,
        r_e,
        v_tx,
        R_DISC,
        ADDR_F,
        f.pvk_a_x,
        f.pvk_a_y,
        f.r_e_x,
        f.r_e_y,
        SIGMA,
        f.v_tilde,
        f.pvk_b_x,
        f.pvk_b_y,
        f.p_r_x,
        f.p_r_y,
        nu,
        f.r_disc_x,
        f.r_disc_y,
        f.v_tilde_disc,
    );
}

#[test]
fn discloses_outbound_amount() {
    run(fixture(), SK_A, R_E, V_TX, NU);
}

#[test(should_fail)]
fn rejects_wrong_amount() {
    // v_tx + 1 breaks DS5 (the ciphertext decrypts to V_TX under s_B).
    run(fixture(), SK_A, R_E, V_TX + 1, NU);
}

#[test(should_fail)]
fn rejects_wrong_originator() {
    // The transfer RECIPIENT's sk cannot satisfy D2 against PVK_A (the
    // originator's account record): the recipient can't impersonate the sender.
    run(fixture(), SK_B, R_E, V_TX, NU);
}

#[test(should_fail)]
fn rejects_wrong_ephemeral() {
    // A different r_e fails DS3 against the event's emitted R_e -- knowing
    // the amount alone is not enough to claim origination.
    run(fixture(), SK_A, R_E + 1, V_TX, NU);
}

#[test(should_fail)]
fn rejects_zero_ephemeral() {
    let mut f = fixture();
    // R_e = O encoding; the r_e != 0 guard fires before any curve math.
    f.r_e_x = 0;
    f.r_e_y = 0;
    run(f, SK_A, 0, V_TX, NU);
}

#[test(should_fail)]
fn rejects_wrong_nonce() {
    // A replay against a different request nonce breaks U3.
    run(fixture(), SK_A, R_E, V_TX, NU + 1);
}

#[test(should_fail)]
fn rejects_substituted_recipient() {
    // Swapping PVK_B for another registered account changes s_B, so DS5
    // no longer decrypts v_tilde: the proof pins WHO was paid, not just
    // how much.
    let mut f = fixture();
    let other = scalar_mul(vk_from_sk(SK_B + 1, ADDR_F), H);
    f.pvk_b_x = other.x;
    f.pvk_b_y = other.y;
    run(f, SK_A, R_E, V_TX, NU);
}

#[test(should_fail)]
fn rejects_negated_recipient_key() {
    // -PVK_B is itself on-curve and shares PVK_B's x-coordinate; absorbing
    // S.y in the ECDH extraction makes it decrypt v_tilde to garbage.
    let mut f = fixture();
    f.pvk_b_y = 0 - f.pvk_b_y;
    run(f, SK_A, R_E, V_TX, NU);
}

#[test]
fn recipient_can_decrypt() {
    // U-block round trip from the disclosure recipient's side.
    let f = fixture();
    let r_disc_point = scalar_mul(R_DISC, H);
    let mask = poseidon_with_domain(DISCLOSURE, [ecdh(R_R, r_disc_point), NU]);
    assert(f.v_tilde_disc - mask == V_TX);
}
