use algebra::Polynomial;
use bfv::{BFVPlaintext, BFVScheme, PlainField};

#[test]
fn bfv_enc_dec_test() {
    let ctx = BFVScheme::gen_context();
    let (sk, pk) = BFVScheme::gen_keypair(&ctx);

    for _ in 0..1000 {
        let msg = Polynomial::<PlainField>::random(ctx.rlwe_dimension(), &mut *ctx.csrng_mut());
        let msg = BFVPlaintext(msg);

        let c = BFVScheme::encrypt(&ctx, &pk, &msg);

        let m = BFVScheme::decrypt(&ctx, &sk, &c);
        assert_eq!(msg, m);
    }
}

#[test]
fn bfv_add_test() {
    let ctx = BFVScheme::gen_context();
    let (sk, pk) = BFVScheme::gen_keypair(&ctx);
    for _ in 0..1000 {
        let m1_poly = Polynomial::<PlainField>::random(ctx.rlwe_dimension(), &mut *ctx.csrng_mut());
        let m1 = BFVPlaintext(m1_poly.clone());

        let m2_poly = Polynomial::<PlainField>::random(ctx.rlwe_dimension(), &mut *ctx.csrng_mut());
        let m2 = BFVPlaintext(m2_poly.clone());

        let m_add = BFVPlaintext(m1_poly + m2_poly);

        let c1 = BFVScheme::encrypt(&ctx, &pk, &m1);
        let c2 = BFVScheme::encrypt(&ctx, &pk, &m2);
        let c3 = BFVScheme::evalute_add(&ctx, &c1, &c2);

        let m3 = BFVScheme::decrypt(&ctx, &sk, &c3);
        assert_eq!(m3, m_add);
    }
}

#[test]
fn bfv_scale_test() {
    let ctx = BFVScheme::gen_context();
    let (sk, pk) = BFVScheme::gen_keypair(&ctx);
    for _ in 0..1000 {
        let m_poly = Polynomial::<PlainField>::random(ctx.rlwe_dimension(), &mut *ctx.csrng_mut());
        let m = BFVPlaintext(m_poly.clone());

        let scale = PlainField::random(&mut *ctx.csrng_mut());
    }
}
