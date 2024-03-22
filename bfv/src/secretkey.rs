//! The secret key of BFV.
use crate::{context::BFVContext, BFVPublicKey, CipherField};
use algebra::{Polynomial, Random};

/// Define the secret key of BFV.
#[derive(Clone, Debug, PartialEq)]
pub struct BFVSecretKey {
    ternary_key: Polynomial<CipherField>,
}

impl BFVSecretKey {
    /// Generate a new BFV secret key with ternary distribution.
    pub fn new(ctx: &BFVContext) -> Self {
        let mut csrng = ctx.csrng_mut();
        let poly = Polynomial::<CipherField>::random_with_dis(
            ctx.rlwe_dimension(),
            &mut *csrng,
            CipherField::ternary_distribution(),
        );
        Self { ternary_key: poly }
    }
    /// Returns the reference of secret key.
    #[inline]
    pub fn secret_key(&self) -> &Polynomial<CipherField> {
        &self.ternary_key
    }

    /// Generate a public key of BFV using the secret key.
    pub fn gen_pubkey(&self, ctx: &BFVContext) -> BFVPublicKey {
        let mut csrng = ctx.csrng_mut();
        let a = Polynomial::<CipherField>::random(ctx.rlwe_dimension(), &mut *csrng);
        let e: Polynomial<CipherField> = Polynomial::<CipherField>::random_with_dis(
            ctx.rlwe_dimension(),
            &mut *csrng,
            CipherField::normal_distribution(0.0, 3.2).unwrap(),
        );
        let b = &a * self.secret_key() + e;
        BFVPublicKey::new([b, -a])
    }
}
