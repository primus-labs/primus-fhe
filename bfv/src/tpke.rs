//! Define threshold pke with BFV.

use algebra::{Field, Polynomial, Random};
use rand::{CryptoRng, Rng};

use crate::{
    BFVCiphertext, BFVContext, BFVPlaintext, BFVPublicKey, BFVScheme, BFVSecretKey, PlainField,
    MAX_USER_NUMBER,
};

/// Define the threshold policy.
#[derive(Debug, Clone)]
pub struct ThresholdPolicy<F: Field + Random> {
    total_number: usize,
    threshold_number: usize,
    lagrange_coeff: Vec<F>,
    indices: Vec<F>,
}

impl<F: Field + Random> ThresholdPolicy<F> {
    /// Create a new instance.
    /// Make sure that no repeated index in `indices`
    pub fn new(total_number: usize, threshold_number: usize, indices: Vec<F>) -> Self {
        assert_eq!(
            indices.len(),
            total_number,
            "indices length is inconsistent with total_number"
        );
        assert!(!indices.contains(&F::ZERO), "indices should not contain 0");
        assert!(
            threshold_number <= total_number,
            "threshold number exceeds total number"
        );
        assert!(
            total_number <= MAX_USER_NUMBER,
            "total number exceeds MAX_USER_NUMBER"
        );

        let mut lagrange_coeff = vec![F::ZERO; total_number];

        for (i, point) in indices.iter().enumerate() {
            let mut points_with_out_i = indices.clone();
            points_with_out_i.retain(|x| *x == *point);

            let numerator = points_with_out_i.iter().fold(F::ONE, |acc, &x| acc * (-x));
            let denominator = points_with_out_i
                .iter()
                .fold(F::ONE, |acc, &x| acc * (*point - x));
            lagrange_coeff[i] = numerator / denominator;
        }

        Self {
            total_number,
            threshold_number,
            lagrange_coeff,
            indices,
        }
    }

    /// Return total_number
    #[inline]
    pub fn total_number(&self) -> usize {
        self.total_number
    }

    /// Return threshold_number
    #[inline]
    pub fn threshold_number(&self) -> usize {
        self.threshold_number
    }

    /// Return the reference of lagrange ceofficient
    #[inline]
    pub fn lagrange_coeff(&self) -> &[F] {
        &self.lagrange_coeff
    }

    /// Return the reference of indices
    #[inline]
    pub fn indices(&self) -> &[F] {
        &self.indices
    }

    /// Securely sharing a message
    pub fn secret_sharing<R>(&self, secret: &Polynomial<F>, rng: &mut R) -> Vec<Polynomial<F>>
    where
        R: Rng + CryptoRng,
    {
        let mut res = vec![vec![F::ZERO; secret.coeff_count()]; self.total_number];

        for (i, m) in secret.iter().enumerate() {
            let mut poly = Polynomial::<F>::random(self.threshold_number, &mut *rng);
            poly[0] = *m;

            for (j, &point) in self.indices.iter().enumerate() {
                res[j][i] = poly.evaluate(point);
            }
        }

        res.into_iter().map(|x| Polynomial::new(x)).collect()
    }
}

/// Define Threshold PKE context.
#[derive(Debug, Clone)]
pub struct ThresholdPKEContext<F: Field + Random> {
    ctx: BFVContext,
    policy: ThresholdPolicy<F>,
}

impl<F: Field + Random> ThresholdPKEContext<F> {
    /// Create a new instance
    #[inline]
    pub fn new(total_number: usize, threshold_number: usize, indices: Vec<F>) -> Self {
        let ctx = BFVContext::new();
        let policy = ThresholdPolicy::new(total_number, threshold_number, indices);
        Self { ctx, policy }
    }

    /// Return the reference of BFV context
    #[inline]
    pub fn bfv_ctx(&self) -> &BFVContext {
        &self.ctx
    }

    /// Return the referance of policy.
    #[inline]
    pub fn policy(&self) -> &ThresholdPolicy<F> {
        &self.policy
    }
}
/// Define the threshold pke scheme.
pub struct ThresholdPKE;

impl ThresholdPKE {
    /// Generate threshold pke context.
    #[inline]
    pub fn gen_context(
        total_number: usize,
        threshold_number: usize,
        indices: Vec<PlainField>,
    ) -> ThresholdPKEContext<PlainField> {
        ThresholdPKEContext::new(total_number, threshold_number, indices)
    }

    /// Generate key pair.
    #[inline]
    pub fn gen_keypair(ctx: &ThresholdPKEContext<PlainField>) -> (BFVSecretKey, BFVPublicKey) {
        BFVScheme::gen_keypair(ctx.bfv_ctx())
    }

    /// Encrypt a message.
    /// First secret sharing the message according to the policy.
    /// Encrypt each share using different pk's of the parties in `indices`
    #[inline]
    pub fn encrypt(
        ctx: &ThresholdPKEContext<PlainField>,
        pks: &Vec<BFVPublicKey>,
        m: &BFVPlaintext,
    ) -> Vec<BFVCiphertext> {
        assert_eq!(
            pks.len(),
            ctx.policy.total_number(),
            "the length of pks should be total_number"
        );
        ctx.policy
            .secret_sharing(&m.0, &mut *ctx.bfv_ctx().csrng_mut())
            .into_iter()
            .zip(pks)
            .map(|(x, pk)| BFVScheme::encrypt(ctx.bfv_ctx(), pk, &BFVPlaintext(x)))
            .collect()
    }

    /// Decrypt the ciphertext.
    #[inline]
    pub fn decrypt(
        ctx: &ThresholdPKEContext<PlainField>,
        sk: &BFVSecretKey,
        c: &BFVCiphertext,
    ) -> BFVPlaintext {
        BFVScheme::decrypt(ctx.bfv_ctx(), sk, c)
    }

    /// Re-encrypt the ciphertext.
    /// First decrypt the ciphertext `c` with `sk`
    /// Encrypt the above message with `pk_new`.
    #[inline]
    pub fn re_encrypt(
        ctx: &ThresholdPKEContext<PlainField>,
        c: &BFVCiphertext,
        sk: &BFVSecretKey,
        pk_new: &BFVPublicKey,
    ) -> BFVCiphertext {
        let m = Self::decrypt(ctx, sk, c);
        BFVScheme::encrypt(ctx.bfv_ctx(), pk_new, &m)
    }

    /// Combine the ciphertext
    #[inline]
    pub fn combine(
        ctx: &ThresholdPKEContext<PlainField>,
        ctxts: &[BFVCiphertext],
    ) -> BFVCiphertext {
        BFVScheme::evaluate_inner_product(ctx.bfv_ctx(), ctxts, ctx.policy.lagrange_coeff())
    }
}
