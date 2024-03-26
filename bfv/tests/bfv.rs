mod tests {
    use algebra::Polynomial;
    use bfv::{BFVCiphertext, BFVPlaintext, BFVScheme, PlainField};

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
            let m1_poly =
                Polynomial::<PlainField>::random(ctx.rlwe_dimension(), &mut *ctx.csrng_mut());
            let m1 = BFVPlaintext(m1_poly.clone());

            let m2_poly =
                Polynomial::<PlainField>::random(ctx.rlwe_dimension(), &mut *ctx.csrng_mut());
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
    fn bfv_mul_scalar_test() {
        let ctx = BFVScheme::gen_context();
        let (sk, pk) = BFVScheme::gen_keypair(&ctx);
        for _ in 0..1000 {
            let m_poly =
                Polynomial::<PlainField>::random(ctx.rlwe_dimension(), &mut *ctx.csrng_mut());
            let m = BFVPlaintext(m_poly.clone());

            let c = BFVScheme::encrypt(&ctx, &pk, &m);

            let scalar = PlainField::random(&mut *ctx.csrng_mut());
            let m_scalar = BFVPlaintext(m_poly.mul_scalar(scalar));

            let c_scalar = BFVScheme::evaluate_mul_scalar(&ctx, &scalar, &c);

            let m_res = BFVScheme::decrypt(&ctx, &sk, &c_scalar);
            assert_eq!(m_scalar, m_res);
        }
    }

    #[test]
    fn bfv_inner_product_test() {
        let ctx = BFVScheme::gen_context();
        let (sk, pk) = BFVScheme::gen_keypair(&ctx);
        const N: usize = 20;

        for _ in 0..200 {
            let mut scalars = Vec::new();
            let mut msgs = Vec::new();
            let mut msgs_poly = Vec::new();
            for i in 0..N {
                msgs_poly.push(Polynomial::<PlainField>::random(
                    ctx.rlwe_dimension(),
                    &mut *ctx.csrng_mut(),
                ));
                msgs.push(BFVPlaintext(msgs_poly[i].clone()));

                scalars.push(PlainField::random(&mut *ctx.csrng_mut()));
            }
            let m_ip = msgs_poly.iter().zip(scalars.iter()).fold(
                Polynomial::<PlainField>::zero(ctx.rlwe_dimension()),
                |acc, (m, s)| acc + m.mul_scalar(*s),
            );

            let m_ip = BFVPlaintext(m_ip);

            let ctxts: Vec<BFVCiphertext> = msgs
                .iter()
                .map(|m| BFVScheme::encrypt(&ctx, &pk, m))
                .collect();

            let c_ip = BFVScheme::evaluate_inner_product(&ctx, &ctxts, &scalars);
            let m_res = BFVScheme::decrypt(&ctx, &sk, &c_ip);

            assert_eq!(m_res, m_ip);
        }
    }
}
