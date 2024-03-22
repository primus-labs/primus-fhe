use algebra::Polynomial;
use bfv::{BFVPlaintext, BFVScheme, PlainField};

#[test]
fn bfv_test() {
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
