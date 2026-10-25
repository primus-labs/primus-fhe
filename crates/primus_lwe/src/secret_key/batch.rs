//! Independent ciphertext batches; message adapters share these streaming kernels.

use super::LweSecretKey;
use crate::LweEncryptionParameters;
use crate::batch::{batch_iter, batch_len, check_batch};
use primus_distr::DiscreteGaussian;
use primus_integer::FheUint;
use primus_lattice::lwe::{LweIter, LweIterMut};
use primus_reduce::RingContext;
use rand::distr::Uniform;

impl<T: FheUint> LweSecretKey<T> {
    /// Encrypts canonical encoded residues into one newly allocated batch.
    /// See [`Self::encrypt_encoded_batch_to`] for contracts. Also panics if
    /// the total storage length overflows.
    #[must_use]
    pub fn encrypt_encoded_batch<M, R>(
        &self,
        plaintexts: &[T],
        params: &LweEncryptionParameters<T, M>,
        rng: &mut R,
    ) -> Vec<T>
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut output = vec![T::ZERO; batch_len(self.dimension(), plaintexts.len())];
        self.encrypt_encoded_batch_to(plaintexts, &mut output, params, rng);
        output
    }

    /// Encrypts canonical encoded residues into existing batch storage.
    ///
    /// No allocation or scratch is needed. Empty batches consume no randomness.
    /// RNG ordering need not match repeated single-message encryption.
    /// Output must contain exactly `plaintexts.len() * (self.dimension() + 1)`
    /// coefficients, with one `[mask, body]` chunk per plaintext.
    ///
    /// # Correctness
    ///
    /// The key must satisfy the [type's parameter contract](Self#correctness).
    /// Every plaintext must be canonical under the parameter modulus.
    ///
    /// # Panics
    ///
    /// Modulus or output length mismatches, or length overflow, panic before writing
    /// or sampling. Debug builds also check the parameter dimension.
    /// A panicking RNG can leave partial output.
    pub fn encrypt_encoded_batch_to<M, R>(
        &self,
        plaintexts: &[T],
        output: &mut [T],
        params: &LweEncryptionParameters<T, M>,
        rng: &mut R,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_modulus(params.cipher_modulus());
        debug_assert_eq!(self.dimension(), params.dimension().get());
        check_batch(output, self.dimension(), plaintexts.len());
        self.encrypt_batch_iter_to(
            plaintexts.iter().copied(),
            output,
            params.cipher_modulus(),
            params.cipher_modulus_uniform_distr(),
            params.noise_distribution(),
            rng,
        );
    }

    /// Allocates canonical phases `b - <a,s>` in ciphertext order.
    /// The correctness conditions of [`Self::decrypt_phase_batch_to`] apply.
    ///
    /// # Panics
    ///
    /// Panics if the recorded key modulus differs from `modulus`, or the input
    /// length is not a multiple of `self.dimension() + 1`.
    /// Empty input returns an empty vector.
    #[must_use]
    pub fn decrypt_phase_batch<M: RingContext<T>>(&self, input: &[T], modulus: M) -> Vec<T> {
        self.check_modulus(modulus);
        self.decrypt_phase_iter(batch_iter(input, self.dimension()), modulus)
            .collect()
    }

    /// Writes canonical phases into an exactly sized output slice without allocating.
    ///
    /// # Correctness
    ///
    /// Every ciphertext and key coefficient must be canonical under `modulus`,
    /// satisfying [`primus_reduce::ReduceDotProduct`].
    ///
    /// # Panics
    ///
    /// Panics before writing if the recorded key modulus differs from `modulus`,
    /// if `input.len() != output.len() * (self.dimension() + 1)`, or if that length
    /// overflows.
    pub fn decrypt_phase_batch_to<M: RingContext<T>>(
        &self,
        input: &[T],
        output: &mut [T],
        modulus: M,
    ) {
        self.check_modulus(modulus);
        let lwe_len = check_batch(input, self.dimension(), output.len());
        let phases = self.decrypt_phase_iter(LweIter::new(input, lwe_len), modulus);
        for (phase, output) in phases.zip(output) {
            *output = phase;
        }
    }

    /// Encrypts one encoded residue per validated output chunk. The owner domain,
    /// sampler compatibility and complete output length are established by the caller;
    /// `plaintexts` must yield exactly one residue per output chunk.
    /// A lazy codec iterator keeps encoding local to each ciphertext, without
    /// collecting plaintexts or changing the single-ciphertext RNG order.
    pub(super) fn encrypt_batch_iter_to<M, R>(
        &self,
        plaintexts: impl Iterator<Item = T>,
        output: &mut [T],
        modulus: M,
        uniform: Uniform<T>,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let key = self.as_view();
        for (mut ciphertext, plaintext) in
            LweIterMut::new(output, self.dimension() + 1).zip(plaintexts)
        {
            key.encrypt_encoded_to(plaintext, &mut ciphertext, modulus, uniform, noise, rng);
        }
    }

    /// Extracts phases after the caller checks the owner domain and full layout.
    /// Keeping this lazy lets message decoding fuse with the phase traversal.
    pub(super) fn decrypt_phase_iter<'a, M: RingContext<T>>(
        &'a self,
        input: LweIter<'a, T>,
        modulus: M,
    ) -> impl Iterator<Item = T> {
        let key = self.as_ref();
        input.map(move |ciphertext| {
            modulus.reduce_sub(
                ciphertext.b(),
                modulus.reduce_dot_product(ciphertext.a(), key),
            )
        })
    }
}
