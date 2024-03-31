//! Define threshold pke with BFV.

use algebra::{Field, Polynomial};
use rand::{CryptoRng, Rng};

use crate::{
    BFVCiphertext, BFVContext, BFVPlaintext, BFVPublicKey, BFVScheme, BFVSecretKey, PlainField,
    MAX_USER_NUMBER,
};

type F = PlainField;

/// Define the threshold policy.
#[derive(Debug, Clone)]
pub struct ThresholdPolicy {
    total_number: usize,
    threshold_number: usize,
    indices: Vec<F>,
}

impl ThresholdPolicy {
    /// Create a new instance.
    /// Make sure that no repeated index in `indices`
    /// `indices` should not contain `0`.
    pub fn new(total_number: usize, threshold_number: usize, indices: Vec<F>) -> Self {
        assert_eq!(
            indices.len(),
            total_number,
            "indices length should be consistent with total_number"
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

        Self {
            total_number,
            threshold_number,
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

        res.into_iter().map(Polynomial::new).collect()
    }
}

/// Define Threshold PKE context.
#[derive(Debug, Clone)]
pub struct ThresholdPKEContext {
    bfv_ctx: BFVContext,
    policy: ThresholdPolicy,
}

impl ThresholdPKEContext {
    /// Create a new instance
    #[inline]
    pub fn new(total_number: usize, threshold_number: usize, indices: Vec<F>) -> Self {
        let bfv_ctx = BFVContext::new();
        let policy = ThresholdPolicy::new(total_number, threshold_number, indices);
        Self { bfv_ctx, policy }
    }

    /// Return the reference of BFV context
    #[inline]
    pub fn bfv_ctx(&self) -> &BFVContext {
        &self.bfv_ctx
    }

    /// Return the referance of policy.
    #[inline]
    pub fn policy(&self) -> &ThresholdPolicy {
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
        indices: Vec<F>,
    ) -> ThresholdPKEContext {
        ThresholdPKEContext::new(total_number, threshold_number, indices)
    }

    /// Compute lagrange coefficients.
    pub fn gen_lagrange_coeffs(chosen_indices: &[F]) -> Vec<F> {
        assert!(
            !chosen_indices.contains(&F::ZERO),
            "indices should not contain 0"
        );
        let mut lagrange_coeff = vec![F::ZERO; chosen_indices.len()];

        for (i, point) in chosen_indices.iter().enumerate() {
            let mut points_without_i = chosen_indices.to_vec();
            points_without_i.retain(|x| *x != *point);

            let numerator = points_without_i.iter().fold(F::ONE, |acc, &x| acc * (-x));
            let denominator = points_without_i
                .iter()
                .fold(F::ONE, |acc, &x| acc * (*point - x));
            lagrange_coeff[i] = numerator / denominator;
        }

        lagrange_coeff
    }

    /// Generate key pair.
    #[inline]
    pub fn gen_keypair(ctx: &ThresholdPKEContext) -> (BFVSecretKey, BFVPublicKey) {
        BFVScheme::gen_keypair(ctx.bfv_ctx())
    }

    /// Encrypt a message.
    /// First secret sharing the message according to the policy.
    /// Encrypt each share using different pk's of the parties in `indices`
    #[inline]
    pub fn encrypt(
        ctx: &ThresholdPKEContext,
        pks: &Vec<BFVPublicKey>,
        m: &BFVPlaintext,
    ) -> Vec<BFVCiphertext> {
        assert_eq!(
            pks.len(),
            ctx.policy.total_number(),
            "the length of pks should be total_number"
        );
        let polys = ctx
            .policy
            .secret_sharing(&m.0, &mut *ctx.bfv_ctx().csrng_mut());
        polys
            .into_iter()
            .zip(pks)
            .map(|(x, pk)| BFVScheme::encrypt(ctx.bfv_ctx(), pk, &BFVPlaintext(x)))
            .collect()
    }

    /// Decrypt the ciphertext.
    #[inline]
    pub fn decrypt(
        ctx: &ThresholdPKEContext,
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
        ctx: &ThresholdPKEContext,
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
        ctx: &ThresholdPKEContext,
        ctxts: &[BFVCiphertext],
        chosen_indices: &[F],
    ) -> BFVCiphertext {
        assert_eq!(
            ctxts.len(),
            chosen_indices.len(),
            "the length of ctxts and chosen_indices should be equal"
        );
        let lagrange_coeff = Self::gen_lagrange_coeffs(chosen_indices);
        BFVScheme::evaluate_inner_product(ctx.bfv_ctx(), ctxts, &lagrange_coeff)
    }
}
