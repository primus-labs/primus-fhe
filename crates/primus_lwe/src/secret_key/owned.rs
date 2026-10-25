use primus_integer::{FheUint, Size};
use primus_reduce::{Modulus, RingContext};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{LweEncryptionParameters, SecretKeyDistr};

use super::LweSecretKeyRef;

/// Represents a secret key for the Learning with Errors (LWE) cryptographic scheme.
///
/// Secret coefficients are erased when the key (including each clone) is dropped.
/// Message operations use [`crate::LweParameters`] for encoding and sampling.
/// Single, batch and packed encoded encryption use [`LweEncryptionParameters`].
/// [`Self::as_view`] borrows the coefficients for single raw operations without
/// the owner's modulus check; those views also support zero-dimensional samples.
/// Batch operations, including encoded encryption and phase decryption,
/// require this owned key, ensuring that reused single-ciphertext operations
/// always receive encoded coefficients.
/// Construction guarantees that the ciphertext length `dimension() + 1` fits
/// in `usize` and records the coefficient modulus as `q - 1`, including the
/// native modulus. This metadata does not establish secret-key identity.
/// Explicit [`Zeroize::zeroize`] erases and clears the coefficient vector;
/// public modulus/distribution metadata remains, but the key must be discarded.
///
/// # Correctness
///
/// Operations require the key and parameters to have the same dimension and
/// ciphertext modulus. Coefficients must be canonical residues under that
/// modulus, satisfying [`primus_reduce::ReduceDotProduct`]. Owning operations
/// check the recorded modulus; raw views cannot perform that check.
#[derive(Clone)]
pub struct LweSecretKey<T: FheUint> {
    data: Vec<T>,
    distr: SecretKeyDistr,
    modulus_minus_one: T,
}

impl<T: FheUint> Zeroize for LweSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for LweSecretKey<T> {}

impl<T: FheUint> Drop for LweSecretKey<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: FheUint> AsRef<[T]> for LweSecretKey<T> {
    #[inline]
    fn as_ref(&self) -> &[T] {
        &self.data
    }
}

impl<T: FheUint> Size for LweSecretKey<T> {
    #[inline]
    fn byte_count(&self) -> usize {
        self.data.byte_count()
    }
}

impl<T: FheUint> LweSecretKey<T> {
    /// Creates a new [`LweSecretKey<T>`].
    ///
    /// # Correctness
    ///
    /// `key` must contain canonical residues under `modulus` and satisfy `distr`.
    /// Neither condition is checked here. The supplied modulus is recorded, not
    /// inferred from coefficients (binary coefficients alone cannot identify it).
    ///
    /// # Panics
    ///
    /// Panics if `key.len() + 1` overflows `usize`.
    #[must_use]
    #[inline]
    pub fn new(key: Vec<T>, distr: SecretKeyDistr, modulus: impl Modulus<ValueT = T>) -> Self {
        key.len().checked_add(1).expect("LWE length overflow");
        Self {
            data: key,
            distr,
            modulus_minus_one: modulus.minus_one(),
        }
    }

    /// Borrows the canonical secret coefficients for raw LWE operations.
    ///
    /// The view carries no modulus metadata. Bind/check the owning key's modulus
    /// before creating this view when the consuming operation accepts parameters.
    #[must_use]
    #[inline]
    pub fn as_view(&self) -> LweSecretKeyRef<'_, T> {
        LweSecretKeyRef::Encoded(self.as_ref())
    }

    /// Returns the dimension of this [`LweSecretKey<T>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.data.len()
    }

    /// Returns the distribution of this [`LweSecretKey<T>`].
    #[inline]
    pub fn distr(&self) -> SecretKeyDistr {
        self.distr
    }

    /// Returns `q - 1` for the modulus recorded at generation or import.
    ///
    /// The native modulus is represented by `T::MAX`; an explicit modulus `q`
    /// uses `q - 1`. This identifies the residue domain, not the secret itself.
    #[must_use]
    #[inline]
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.modulus_minus_one
    }

    /// Checks the owning boundary before discarding domain metadata in a raw view.
    #[inline]
    pub(crate) fn check_modulus(&self, modulus: impl Modulus<ValueT = T>) {
        assert_eq!(
            self.modulus_minus_one,
            modulus.minus_one(),
            "LWE secret-key ciphertext modulus mismatch"
        );
    }

    /// Generates a new [`LweSecretKey<T>`] with random values.
    /// Partial secret storage is erased if sampling unwinds.
    #[inline]
    pub fn generate<R, M>(params: &LweEncryptionParameters<T, M>, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        // Own the allocation before sampling so unwinding erases partial secrets.
        let mut key = Self {
            data: vec![T::ZERO; params.dimension().get()],
            distr: params.secret_key_distr(),
            modulus_minus_one: params.cipher_modulus_minus_one(),
        };
        params
            .secret_key_sampler()
            .sample_encoded_to(&mut key.data, key.modulus_minus_one, rng);
        key
    }
}
