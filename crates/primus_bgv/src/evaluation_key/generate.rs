//! Prepare secret-dependent source polynomials and generate native columns.
use std::{borrow::Cow, sync::Arc};

use primus_factor::{FactorSliceOps, ShoupFactor};
use primus_glwe_rns::DcrtGlweSecretKey;
use primus_ntt::NttAutomorphismPermutation;
use primus_poly::DcrtPolynomial;
use primus_reduce::{Reduce, ReduceMul};
use rand::distr::Uniform;
use zeroize::Zeroizing;

use crate::{BgvClient, BgvContext};

use super::{
    BgvEvaluationKeyConfig, BgvEvaluationKeyError,
    backend::{KeyBase, NativeEvaluationBasis},
    error::{
        validate_level, validate_ordered_moduli, validate_plaintext_modulus, validate_ring_length,
    },
    material::{
        BgvAutomorphismKey, BgvKeySwitchingKey, BgvRelinearizationKey, NativeEvaluationKey,
    },
};

enum KeySecret<'s> {
    Radix(&'s [u64]),
    Hybrid(Zeroizing<Vec<u64>>),
}

impl AsRef<[u64]> for KeySecret<'_> {
    fn as_ref(&self) -> &[u64] {
        match self {
            Self::Radix(secret) => secret,
            Self::Hybrid(secret) => secret,
        }
    }
}

impl NativeEvaluationKey {
    fn prepare_secret<'s>(
        &self,
        context: &BgvContext,
        key: &'s DcrtGlweSecretKey<u64>,
    ) -> Result<KeySecret<'s>, BgvEvaluationKeyError> {
        let input = key.iter_dcrt_poly().next().expect("rank-one secret");
        match &self.basis {
            NativeEvaluationBasis::Radix(_) => {
                Ok(KeySecret::Radix(&input.0[..self.key_poly_len()]))
            }
            NativeEvaluationBasis::Hybrid(parameters) => Ok(KeySecret::Hybrid(
                parameters.extend_bounded_secret_to_qp(
                    input.as_ref(),
                    context.parameters().base_q(),
                    context.table(),
                    context
                        .parameters()
                        .encryption_parameters()
                        .secret_key_sampler()
                        .maximum_magnitude(),
                )?,
            )),
        }
    }

    // Collective relin holds an owned private key-domain share across rounds.
    pub(super) fn secret(
        &self,
        context: &BgvContext,
        key: &DcrtGlweSecretKey<u64>,
    ) -> Result<Zeroizing<Vec<u64>>, BgvEvaluationKeyError> {
        Ok(match self.prepare_secret(context, key)? {
            KeySecret::Radix(secret) => Zeroizing::new(secret.to_vec()),
            KeySecret::Hybrid(secret) => secret,
        })
    }

    pub(super) fn noise(
        &self,
        context: &BgvContext,
        output: &mut [u64],
        rng: &mut impl rand::CryptoRng,
    ) {
        let base = self.key_base();
        context
            .parameters()
            .encryption_parameters()
            .sample_noise_to(output, base.moduli_values(), rng);
        if self.is_hybrid() {
            scale_with_p(self.p, self.n, base, output);
        }
        self.basis.transform_to_ntt(context, output);
    }

    pub(super) fn uniform_distributions<'c>(
        &self,
        context: &'c BgvContext,
    ) -> Cow<'c, [Uniform<u64>]> {
        let basis = self.key_base();
        if self.is_hybrid() {
            return Cow::Owned(
                basis
                    .moduli_values()
                    .iter()
                    .map(|&q| Uniform::new(0, q).expect("positive modulus"))
                    .collect(),
            );
        }
        Cow::Borrowed(
            &context
                .parameters()
                .encryption_parameters()
                .cipher_moduli_uniform_distr()[..basis.moduli_count()],
        )
    }

    fn encrypt(
        mut self,
        context: &BgvContext,
        source: &[u64],
        target: &[u64],
        rng: &mut impl rand::CryptoRng,
    ) -> Self {
        let len = self.key_poly_len();
        let uniforms = self.uniform_distributions(context);
        let moduli = self.key_base().moduli();
        let mut columns = vec![0; self.key_len()];
        // Native Radix lifts p*g_j in Q. Hybrid weights already contain P,
        // and its error is scaled in coefficients before the QP transform.
        let mut scaled_weights = (!self.is_hybrid()).then(|| vec![0; moduli.len()]);
        for (digit, column) in columns.chunks_exact_mut(2 * len).enumerate() {
            let weights = self.weights(digit);
            let (body, mask) = column.split_at_mut(len);
            self.noise(context, body, rng);
            let weights = if let Some(scaled) = &mut scaled_weights {
                scale_with_p(self.p, self.n, self.key_base(), body);
                for ((out, &weight), q) in scaled.iter_mut().zip(weights).zip(moduli) {
                    *out = q.reduce_mul(weight, self.p);
                }
                scaled.as_slice()
            } else {
                weights
            };
            primus_distr::sample_crt_uniform_values_to(mask, self.n, &uniforms, rng);
            let mut body = DcrtPolynomial(body);
            body.add_mul_scalar_assign(&DcrtPolynomial(source), weights, self.n, moduli);
            body.sub_mul_assign(
                &DcrtPolynomial(&*mask),
                &DcrtPolynomial(target),
                self.n,
                moduli,
            );
        }
        self.columns = columns;
        self
    }
}

pub(super) fn scale_with_p(p: u64, n: usize, base: &KeyBase, values: &mut [u64]) {
    for (i, limb) in values.chunks_exact_mut(n).enumerate() {
        let q = base.moduli()[i % base.moduli_count()];
        // p may exceed an auxiliary prime. Prepare its canonical factor once
        // per limb, then use the native batch kernel for the complete limb.
        ShoupFactor::new(q.reduce(p), q.value()).factor_mul_slice_assign(limb, q.value());
    }
}

// Final key columns must be copied out of the authenticated sums. Fuse that
// copy with Radix p-scaling instead of reading and writing the column twice.
pub(super) fn scale_with_p_to(
    p: u64,
    n: usize,
    base: &KeyBase,
    values: &[u64],
    output: &mut [u64],
) {
    debug_assert_eq!(values.len(), output.len());
    for (i, (input, output)) in values
        .chunks_exact(n)
        .zip(output.chunks_exact_mut(n))
        .enumerate()
    {
        let q = base.moduli()[i % base.moduli_count()];
        ShoupFactor::new(q.reduce(p), q.value()).factor_mul_slice_to(input, output, q.value());
    }
}

impl BgvClient<'_> {
    /// Generates native s²-to-s columns under the selected radix/Hybrid basis.
    ///
    /// Radix phases are p*g_j*s²+p*e_j in Q; Hybrid phases are
    /// P*projector_j*s²+p*e_j in QP. Key modulus/noise are caller budget inputs.
    ///
    /// Temporary secret-square storage is erased on return or unwind.
    /// # Errors
    /// Rejects unsupported levels, radix or digit counts before sampling.
    pub fn relinearization_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        config: impl Into<BgvEvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BgvRelinearizationKey, BgvEvaluationKeyError> {
        let key = NativeEvaluationKey::prepare_metadata(self.context, level, config)?;
        let secret = key.prepare_secret(self.context, self.secret_key())?;
        let mut square = Zeroizing::new(secret.as_ref().to_vec());
        DcrtPolynomial(square.as_mut_slice()).mul_assign(
            &DcrtPolynomial(secret.as_ref()),
            self.context.parameters().poly_length().get(),
            key.key_base().moduli(),
        );
        Ok(BgvRelinearizationKey {
            key: key.encrypt(self.context, &square, secret.as_ref(), rng),
        })
    }

    /// Generates native σ(s)-to-s columns for X -> X^exponent.
    /// The selected key representation follows [`Self::relinearization_key`].
    ///
    /// Temporary transformed-secret storage is erased on return or unwind.
    /// # Errors
    /// Rejects invalid exponents, levels or decomposition before sampling.
    pub fn automorphism_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        exponent: usize,
        config: impl Into<BgvEvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BgvAutomorphismKey, BgvEvaluationKeyError> {
        let n = self.context.parameters().poly_length().get();
        if exponent >= 2 * n || exponent & 1 == 0 {
            return Err(BgvEvaluationKeyError::Exponent {
                exponent,
                twice_n: 2 * n,
            });
        }
        let key = NativeEvaluationKey::prepare_metadata(self.context, level, config)?;
        let permutation =
            NttAutomorphismPermutation::new(exponent, self.context.parameters().poly_length());
        let secret = key.prepare_secret(self.context, self.secret_key())?;
        let secret = secret.as_ref();
        let mut transformed = Zeroizing::new(vec![0; secret.len()]);
        for (input, output) in secret.chunks_exact(n).zip(transformed.chunks_exact_mut(n)) {
            permutation.apply_to(input, output);
        }
        Ok(BgvAutomorphismKey {
            key: key.encrypt(self.context, &transformed, secret, rng),
            exponent,
            permutation,
        })
    }

    /// Generates a row-left rotation key using signed steps in the encoder's layout.
    ///
    /// Negative steps rotate right; steps wrap modulo half the encoder capacity.
    /// The encoder may use an n<N plaintext subring; the ciphertext and secret
    /// remain full N. This returns the existing automorphism key role.
    /// # Correctness
    /// The encoder's plaintext p must be prime, as required by its constructor.
    /// # Errors
    /// Rejects a different plaintext modulus or n>N before sampling, followed by
    /// [`Self::automorphism_key`]'s level and decomposition checks.
    #[cfg(feature = "batching")]
    pub fn row_rotation_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        encoder: &primus_encoding::BatchingEncoder,
        steps: isize,
        config: impl Into<BgvEvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BgvAutomorphismKey, BgvEvaluationKeyError> {
        self.validate_batching_encoder(encoder)?;
        self.automorphism_key(level, encoder.rotation_exponent(steps), config, rng)
    }

    /// Generates a key swapping the encoder's two rows without reversing them.
    ///
    /// The full-ring/subring, correctness and error contracts are
    /// [`Self::row_rotation_key`]'s; only the row permutation differs.
    #[cfg(feature = "batching")]
    pub fn row_swap_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        encoder: &primus_encoding::BatchingEncoder,
        config: impl Into<BgvEvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BgvAutomorphismKey, BgvEvaluationKeyError> {
        self.validate_batching_encoder(encoder)?;
        self.automorphism_key(level, encoder.row_swap_exponent(), config, rng)
    }

    #[cfg(feature = "batching")]
    fn validate_batching_encoder(
        &self,
        encoder: &primus_encoding::BatchingEncoder,
    ) -> Result<(), BgvEvaluationKeyError> {
        let parameters = self.context.parameters();
        let expected = parameters.plain_modulus().value();
        let actual = encoder.plain_modulus();
        if expected != actual {
            return Err(BgvEvaluationKeyError::PlainModulus { expected, actual });
        }
        let maximum = parameters.poly_length().get();
        let actual = encoder.slot_capacity();
        if actual > maximum {
            return Err(BgvEvaluationKeyError::SlotCapacity { maximum, actual });
        }
        Ok(())
    }

    /// Generates a key switching source ciphertexts to this client's secret.
    ///
    /// # Correctness
    /// The callers maintain the intended source/target secret identities and
    /// matching NTT representation. Numeric equality does not establish identity.
    /// # Errors
    /// Rejects different N, p, ordered level bases or decomposition before sampling.
    pub fn key_switching_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        source: &BgvClient<'_>,
        level: usize,
        config: impl Into<BgvEvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BgvKeySwitchingKey, BgvEvaluationKeyError> {
        if !Arc::ptr_eq(self.context.identity(), source.context.identity()) {
            validate_level(self.context, level)?;
            validate_level(source.context, level)?;
            validate_ring_length(
                self.context.parameters().poly_length().get(),
                source.context.parameters().poly_length().get(),
            )?;
            validate_plaintext_modulus(
                self.context.parameters().plain_modulus().value(),
                source.context.parameters().plain_modulus().value(),
            )?;
            validate_ordered_moduli(
                self.context.base_q(level).moduli_values(),
                source.context.base_q(level).moduli_values(),
            )?;
            return Err(BgvEvaluationKeyError::ContextMismatch);
        }
        let key = NativeEvaluationKey::prepare_metadata(self.context, level, config)?;
        let source = key.prepare_secret(source.context, source.secret_key())?;
        let target = key.prepare_secret(self.context, self.secret_key())?;
        Ok(BgvKeySwitchingKey {
            key: key.encrypt(self.context, source.as_ref(), target.as_ref(), rng),
        })
    }
}
