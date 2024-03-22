//! The BFV scheme.

use algebra::{Field, Polynomial, Random};

use crate::{
    plaintext::BFVPlaintext, BFVCiphertext, BFVContext, BFVPublicKey, BFVSecretKey, CipherField,
    PlainField,
};

/// Define the BFV scheme.
pub struct BFVScheme;

impl BFVScheme {
    /// Generate context.
    #[inline]
    pub fn gen_context() -> BFVContext {
        BFVContext::new()
    }

    /// Generate key pair.
    pub fn gen_keypair(ctx: &BFVContext) -> (BFVSecretKey, BFVPublicKey) {
        let sk = BFVSecretKey::new(ctx);
        let pk = sk.gen_pubkey(ctx);
        (sk, pk)
    }

    /// Encrypt with public key.
    pub fn encrypt(ctx: &BFVContext, pk: &BFVPublicKey, m: &BFVPlaintext) -> BFVCiphertext {
        let BFVPublicKey([b, a]) = pk;
        let mut csrng = ctx.csrng_mut();
        let u = Polynomial::<CipherField>::random_with_dis(
            ctx.rlwe_dimension(),
            &mut *csrng,
            CipherField::ternary_distribution(),
        );

        let e1 = Polynomial::<CipherField>::random_with_dis(
            ctx.rlwe_dimension(),
            &mut *csrng,
            CipherField::normal_distribution(0.0, 3.2).unwrap(),
        );

        let e2 = Polynomial::<CipherField>::random_with_dis(
            ctx.rlwe_dimension(),
            &mut *csrng,
            CipherField::normal_distribution(0.0, 3.2).unwrap(),
        );

        let t = PlainField::modulus_value() as u64;
        let q = CipherField::modulus_value() as u64;
        let half_t_minus_1 = (t - 1) / 2;
        let half_t = t / 2;

        let round = |x: &PlainField| {
            let value = x.cast_into_usize() as u64;
            if value > half_t_minus_1 {
                let minus_value = t - value;
                // nearest round of (q * value)/t
                CipherField::from((q - ((q * minus_value + half_t) / t)) as u32)
            } else {
                CipherField::from(((q * value + half_t) / t) as u32)
            }
        };

        let m: Vec<CipherField> =
            m.0.iter()
                .map(
                    #[inline(always)]
                    |x| round(x),
                )
                .collect();
        let m = Polynomial::from_slice(&m);

        let c1 = b * &u + e1 + m;
        let c2 = a * u + e2;
        BFVCiphertext([c1, c2])
    }

    /// Decrypt with secret key.
    pub fn decrypt(_ctx: &BFVContext, sk: &BFVSecretKey, c: &BFVCiphertext) -> BFVPlaintext {
        let sk = sk.secret_key();
        let BFVCiphertext([c1, c2]) = c;

        let t = PlainField::modulus_value() as u64;
        let q = CipherField::modulus_value() as u64;
        let half_q_minus_1 = (q - 1) / 2;
        let half_q = q / 2;

        let round = |x: &CipherField| {
            let value = x.cast_into_usize() as u64;
            if value > half_q_minus_1 {
                let minus_value = q - value;
                // t * value / q
                PlainField::from((t - (t * minus_value + half_q) / q) as u16)
            } else {
                PlainField::from(((t * value + half_q) / q) as u16)
            }
        };
        let msg = c1 + c2 * sk;
        let msg: Vec<PlainField> = msg
            .iter()
            .map(
                #[inline]
                |m| round(m),
            )
            .collect();
        BFVPlaintext(Polynomial::<PlainField>::from_slice(&msg))
    }

    /// Scale multiplication .
    pub fn evaluate_scale(
        _ctx: BFVContext,
        scalar: &PlainField,
        c: &BFVCiphertext,
    ) -> BFVCiphertext {
        let scalar = scalar.to_f64() as u32;
        let BFVCiphertext([c1, c2]) = c;
        let c1 = c1.mul_scalar(scalar);
        let c2 = c2.mul_scalar(scalar);
        BFVCiphertext([c1, c2])
    }

    /// Addition
    pub fn evalute_add(
        _ctx: BFVContext,
        c_lhs: &BFVCiphertext,
        c_rhs: &BFVCiphertext,
    ) -> BFVCiphertext {
        let c1 = &c_lhs.0[0] + &c_rhs.0[0];
        let c2 = &c_lhs.0[1] + &c_rhs.0[1];
        BFVCiphertext([c1, c2])
    }
}

#[test]
fn value_test() {
    let a = 0_u16;
    let b = 1_u16;

    println!("{}", (a as i16) - (b as i16));
}