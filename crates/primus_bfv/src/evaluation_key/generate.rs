//! Secret-dependent source polynomials and native key column encryption.
use std::sync::Arc;

use primus_glwe_rns::DcrtGlweSecretKey;
use primus_ntt::NttAutomorphismPermutation;
use primus_poly::DcrtPolynomial;
use primus_reduce::{ReduceAdd, ReduceMul, ReduceSub};
use zeroize::Zeroizing;

use crate::{BfvClient, BfvContext};

use super::{
    BfvEvaluationKeyConfig, BfvEvaluationKeyError,
    backend::NativeEvaluationBasis,
    material::{
        BfvAutomorphismKey, BfvKeySwitchingKey, BfvRelinearizationKey, NativeEvaluationKey,
    },
};

impl NativeEvaluationKey {
    pub(super) fn noise_to<R: rand::Rng + rand::CryptoRng>(
        &self,
        context: &BfvContext,
        output: &mut [u64],
        rng: &mut R,
    ) {
        sample_noise_to(&self.basis, context, output, rng);
    }

    pub(super) fn secret(
        &self,
        context: &BfvContext,
        key: &DcrtGlweSecretKey<u64>,
    ) -> Result<Zeroizing<Vec<u64>>, BfvEvaluationKeyError> {
        let input = key.iter_dcrt_poly().next().expect("rank-one secret");
        match &self.basis {
            NativeEvaluationBasis::Radix(_) => Ok(Zeroizing::new(
                input.as_ref()[..self.key_poly_len()].to_vec(),
            )),
            NativeEvaluationBasis::Hybrid(parameters) => {
                let bound = context
                    .parameters()
                    .encryption_parameters()
                    .secret_key_sampler()
                    .maximum_magnitude();
                Ok(parameters.extend_bounded_secret_to_qp(
                    input.as_ref(),
                    context.parameters().base_q(),
                    context.table(),
                    bound,
                )?)
            }
        }
    }

    // Each column is native [c0,c1] with c0 = e - c1*s + weight*source.
    // Write noise into the final body so Hybrid needs no per-column allocation.
    fn encrypt<R: rand::Rng + rand::CryptoRng>(
        mut self,
        context: &BfvContext,
        source: &[u64],
        target: &[u64],
        rng: &mut R,
    ) -> Self {
        let len = self.key_poly_len();
        self.columns.resize(self.key_len(), 0);
        match &self.basis {
            NativeEvaluationBasis::Radix(parameters) => {
                let target = DcrtPolynomial(target);
                let moduli = parameters.base_q().moduli();
                let sampling = context.parameters().encryption_parameters();
                let uniforms = &sampling.cipher_moduli_uniform_distr()[..moduli.len()];
                for (index, column) in self.columns.chunks_exact_mut(2 * len).enumerate() {
                    let (body, mask) = column.split_at_mut(len);
                    sample_noise_to(&self.basis, context, body, rng);
                    primus_distr::sample_crt_uniform_values_to(mask, self.n, uniforms, rng);
                    let mut body = DcrtPolynomial(body);
                    body.sub_mul_assign(&DcrtPolynomial(&*mask), &target, self.n, moduli);
                    body.add_mul_scalar_assign(
                        &DcrtPolynomial(source),
                        parameters.key_weights(index),
                        self.n,
                        moduli,
                    );
                }
            }
            NativeEvaluationBasis::Hybrid(parameters) => {
                let uniforms: Vec<_> = self
                    .key_moduli_values()
                    .iter()
                    .map(|&q| rand::distr::Uniform::new(0, q).expect("validated modulus"))
                    .collect();
                let moduli = parameters.hybrid_rns().qp_base().moduli();
                for (index, column) in self.columns.chunks_exact_mut(2 * len).enumerate() {
                    let (body, mask) = column.split_at_mut(len);
                    sample_noise_to(&self.basis, context, body, rng);
                    primus_distr::sample_crt_uniform_values_to(mask, self.n, &uniforms, rng);
                    for ((((body, mask), secret), source), (&weight, modulus)) in body
                        .chunks_exact_mut(self.n)
                        .zip(mask.chunks_exact(self.n))
                        .zip(target.chunks_exact(self.n))
                        .zip(source.chunks_exact(self.n))
                        .zip(parameters.key_weights(index).iter().zip(moduli))
                    {
                        for (((out, &mask), &secret), &source) in
                            body.iter_mut().zip(mask).zip(secret).zip(source)
                        {
                            *out = modulus.reduce_add(
                                modulus.reduce_sub(*out, modulus.reduce_mul(mask, secret)),
                                modulus.reduce_mul(weight, source),
                            );
                        }
                    }
                }
            }
        }
        self
    }
}

fn sample_noise_to<R: rand::Rng + rand::CryptoRng>(
    basis: &NativeEvaluationBasis,
    context: &BfvContext,
    output: &mut [u64],
    rng: &mut R,
) {
    context
        .parameters()
        .encryption_parameters()
        .sample_noise_to(output, basis.key_base().moduli_values(), rng);
    basis.transform_to_ntt(context, output);
}

impl BfvClient<'_> {
    /// Generates g_j*s²+e_j columns under this client's actual secret.
    ///
    /// Temporary secret-square storage is erased on return or unwind.
    /// # Errors
    /// Rejects unsupported levels, radix/Hybrid geometry, secret support or
    /// unrepresentable key noise before sampling.
    pub fn relinearization_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        config: impl Into<BfvEvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BfvRelinearizationKey, BfvEvaluationKeyError> {
        let key = NativeEvaluationKey::prepare_metadata(self.context, level, config)?;
        let secret = key.secret(self.context, self.secret_key())?;
        let mut square = Zeroizing::new(secret.to_vec());
        DcrtPolynomial(square.as_mut_slice()).mul_assign(
            &DcrtPolynomial(secret.as_slice()),
            key.n,
            key.key_moduli(),
        );
        Ok(BfvRelinearizationKey {
            key: key.encrypt(self.context, &square, &secret, rng),
        })
    }

    /// Generates g_j*σ(s)+e_j columns for X -> X^exponent under s.
    ///
    /// Temporary transformed-secret storage is erased on return or unwind.
    /// # Errors
    /// Rejects invalid exponents, levels or decomposition before sampling.
    pub fn automorphism_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        exponent: usize,
        config: impl Into<BfvEvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BfvAutomorphismKey, BfvEvaluationKeyError> {
        let n = self.context.parameters().poly_length().get();
        if exponent >= 2 * n || exponent & 1 == 0 {
            return Err(BfvEvaluationKeyError::Exponent {
                exponent,
                twice_n: 2 * n,
            });
        }
        let key = NativeEvaluationKey::prepare_metadata(self.context, level, config)?;
        let permutation =
            NttAutomorphismPermutation::new(exponent, self.context.parameters().poly_length());
        let secret = key.secret(self.context, self.secret_key())?;
        let mut transformed = Zeroizing::new(vec![0; key.key_poly_len()]);
        for (input, output) in secret.chunks_exact(n).zip(transformed.chunks_exact_mut(n)) {
            permutation.apply_to(input, output);
        }
        Ok(BfvAutomorphismKey {
            key: key.encrypt(self.context, &transformed, &secret, rng),
            exponent,
            permutation,
        })
    }

    /// Generates a key rotating each plaintext row left by signed `steps`.
    ///
    /// Negative steps rotate right; steps wrap modulo half the encoder capacity.
    /// A smaller plaintext subring is supported without resizing the secret or
    /// ciphertext ring. The key retains the selected level and can be bound with
    /// [`BfvAutomorphism::try_new`](crate::evaluation::BfvAutomorphism::try_new). No encoder table or scratch is cloned.
    ///
    /// # Errors
    /// Rejects a different plaintext modulus or capacity above N, then applies
    /// [`Self::automorphism_key`]'s checks. All errors precede random sampling.
    #[cfg(feature = "batching")]
    pub fn row_rotation_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        encoder: &primus_encoding::BatchingEncoder,
        steps: isize,
        config: impl Into<BfvEvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BfvAutomorphismKey, BfvEvaluationKeyError> {
        self.validate_batching_encoder(encoder)?;
        self.automorphism_key(level, encoder.rotation_exponent(steps), config, rng)
    }

    /// Generates a key swapping the encoder's two rows without reversing them.
    /// The geometry, level and pre-sampling error checks are
    /// [`Self::row_rotation_key`]'s; no rotation-step configuration is needed.
    #[cfg(feature = "batching")]
    pub fn row_swap_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        encoder: &primus_encoding::BatchingEncoder,
        config: impl Into<BfvEvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BfvAutomorphismKey, BfvEvaluationKeyError> {
        self.validate_batching_encoder(encoder)?;
        self.automorphism_key(level, encoder.row_swap_exponent(), config, rng)
    }

    #[cfg(feature = "batching")]
    fn validate_batching_encoder(
        &self,
        encoder: &primus_encoding::BatchingEncoder,
    ) -> Result<(), BfvEvaluationKeyError> {
        let expected = self.context.parameters().codec().t();
        let actual = encoder.plain_modulus();
        if actual != expected {
            return Err(BfvEvaluationKeyError::PlainModulus { expected, actual });
        }
        let maximum = self.context.parameters().poly_length().get();
        let actual = encoder.slot_capacity();
        if actual > maximum {
            return Err(BfvEvaluationKeyError::SlotCapacity { maximum, actual });
        }
        Ok(())
    }

    /// Generates a key switching source ciphertexts to this client's secret.
    ///
    /// # Correctness
    /// The callers maintain the intended source/target secret identities and
    /// matching NTT representation. Numeric equality does not establish identity.
    /// # Errors
    /// Rejects clients from different local contexts, an unavailable level, or
    /// incompatible key parameters before sampling.
    pub fn key_switching_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        source: &BfvClient<'_>,
        level: usize,
        config: impl Into<BfvEvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BfvKeySwitchingKey, BfvEvaluationKeyError> {
        if !Arc::ptr_eq(self.context.identity(), source.context.identity()) {
            return Err(BfvEvaluationKeyError::ContextMismatch);
        }
        let key = NativeEvaluationKey::prepare_metadata(self.context, level, config)?;
        let source = key.secret(source.context, source.secret_key())?;
        let target_qp;
        let target = match &key.basis {
            NativeEvaluationBasis::Radix(_) => {
                let target = self
                    .secret_key()
                    .iter_dcrt_poly()
                    .next()
                    .expect("rank-one secret");
                &target.0[..key.key_poly_len()]
            }
            NativeEvaluationBasis::Hybrid(_) => {
                target_qp = key.secret(self.context, self.secret_key())?;
                target_qp.as_slice()
            }
        };
        Ok(BfvKeySwitchingKey {
            key: key.encrypt(self.context, &source, target, rng),
        })
    }
}
