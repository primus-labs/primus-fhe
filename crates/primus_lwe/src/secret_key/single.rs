//! Codec-free single-ciphertext operations retaining the owning key's domain check.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::lwe::Lwe;
use primus_reduce::RingContext;

use crate::{LweCiphertext, LweEncryptionParameters};

use super::LweSecretKey;

impl<T: FheUint> LweSecretKey<T> {
    /// Allocates an encryption of an already encoded residue. Zero encrypts zero.
    ///
    /// Uses the direct initialization and RNG order of
    /// [`super::LweSecretKeyRef::encrypt_encoded`], without message scaling.
    ///
    /// # Correctness
    ///
    /// The key must satisfy the [type's parameter contract](Self#correctness).
    /// `plaintext` must be canonical under the parameter modulus.
    ///
    /// # Panics
    ///
    /// Panics before allocating or sampling if the recorded key modulus differs
    /// from `params`. Debug builds also check the parameter dimension.
    #[must_use]
    #[inline]
    pub fn encrypt_encoded<M, R>(
        &self,
        plaintext: T,
        params: &LweEncryptionParameters<T, M>,
        rng: &mut R,
    ) -> LweCiphertext<T>
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_modulus(params.cipher_modulus());
        debug_assert_eq!(self.dimension(), params.dimension().get());
        self.as_view().encrypt_encoded(
            plaintext,
            params.cipher_modulus(),
            params.cipher_modulus_uniform_distr(),
            params.noise_distribution(),
            rng,
        )
    }

    /// Overwrites a ciphertext with an encryption of a canonical encoded residue.
    ///
    /// No allocation or message scaling occurs. The correctness requirements of
    /// [`Self::encrypt_encoded`] apply.
    ///
    /// # Panics
    ///
    /// Panics before writing or sampling on a recorded modulus or output dimension
    /// mismatch. Debug builds also check the parameter dimension. A panicking RNG
    /// can leave partial output, as in [`super::LweSecretKeyRef::encrypt_encoded_to`].
    #[inline]
    pub fn encrypt_encoded_to<M, R>(
        &self,
        plaintext: T,
        output: &mut Lwe<impl DataMut<Elem = T>>,
        params: &LweEncryptionParameters<T, M>,
        rng: &mut R,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_modulus(params.cipher_modulus());
        debug_assert_eq!(self.dimension(), params.dimension().get());
        self.as_view().encrypt_encoded_to(
            plaintext,
            output,
            params.cipher_modulus(),
            params.cipher_modulus_uniform_distr(),
            params.noise_distribution(),
            rng,
        );
    }

    /// Returns the canonical phase `b - <a,s>` without decoding or allocating.
    ///
    /// # Correctness
    ///
    /// The ciphertext and key coefficients must be canonical under `modulus`,
    /// satisfying [`super::LweSecretKeyRef::decrypt_phase`].
    ///
    /// # Panics
    ///
    /// Panics if the recorded modulus differs, the ciphertext has no body, or
    /// the ciphertext's mask and key lengths differ.
    #[must_use]
    #[inline]
    pub fn decrypt_phase<M: RingContext<T>>(
        &self,
        input: &Lwe<impl Data<Elem = T>>,
        modulus: M,
    ) -> T {
        self.check_modulus(modulus);
        self.as_view().decrypt_phase(input, modulus)
    }
}
