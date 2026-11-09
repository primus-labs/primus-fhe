//! Canonical coefficient-domain NTRU secret key.

use num_traits::ConstZero;
use primus_integer::FheUint;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{NtruEncryptionParameters, SecretKeyDistr};

/// A small signed polynomial `f` shared by all NTRU transform backends.
///
/// Signed coefficients are intentionally stored independently of a ciphertext
/// modulus: `-1` is encoded as `q - 1` for NTT and as the native two's-complement
/// bit pattern for Fourier only when the key is converted to that backend.
/// Conversion to an explicit modulus `q` requires every coefficient's unsigned
/// magnitude to be strictly less than `q`. Generated keys satisfy this bound
/// for their parameter modulus; imported keys and conversions to another
/// modulus retain this caller obligation.
/// Secret storage, including spare capacity, is securely erased on drop.
#[derive(Clone)]
pub struct NtruSecretKey<T: FheUint> {
    pub(crate) key: Vec<T::SignedInteger>,
    pub(crate) distr: SecretKeyDistr,
}

impl<T: FheUint> Zeroize for NtruSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for NtruSecretKey<T> {}

impl<T: FheUint> Drop for NtruSecretKey<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: FheUint> NtruSecretKey<T> {
    /// Owns the candidate buffer before sampling so unwinding erases partial
    /// secrets. Rejection sampling reuses this allocation, and padded sampling
    /// overwrites only the active prefix, leaving the zero suffix intact.
    pub(super) fn allocate(poly_length: usize, distr: SecretKeyDistr) -> Self {
        Self {
            key: vec![T::SignedInteger::ZERO; poly_length],
            distr,
        }
    }

    /// Creates a coefficient-domain NTRU key from signed values.
    ///
    /// No modulus is attached to this key. Before using an explicit-modulus
    /// backend, the caller must ensure that every coefficient has unsigned
    /// magnitude less than the target modulus. `distr` records the sampling
    /// distribution; it does not validate the supplied coefficients.
    ///
    /// # Panics
    ///
    /// Panics if `key` is empty.
    #[inline]
    pub fn new(key: Vec<T::SignedInteger>, distr: SecretKeyDistr) -> Self {
        let secret_key = Self { key, distr };
        assert!(
            !secret_key.key.is_empty(),
            "NTRU secret key must not be empty"
        );
        secret_key
    }

    /// Returns the coefficient polynomial length.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.key.len()
    }

    /// Returns the proposal distribution. Transform-domain key generation
    /// conditions it on invertibility and, for Fourier, the numerical guard.
    #[inline]
    pub fn distr(&self) -> SecretKeyDistr {
        self.distr
    }

    /// Returns the canonical signed coefficients of `f`.
    #[inline]
    pub fn as_slice(&self) -> &[T::SignedInteger] {
        &self.key
    }

    /// Samples a coefficient key from `params`.
    ///
    /// This method does not impose backend-specific invertibility. Use
    /// `NttNtruSecretKey::generate` (feature `ntt`) or
    /// `FourierNtruSecretKey::generate` (feature `fourier`) when an immediately
    /// usable encryption key is required.
    pub fn generate<R, M>(params: &NtruEncryptionParameters<T, M>, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: primus_reduce::RingContext<T>,
    {
        let mut secret_key = Self::allocate(params.poly_length().get(), params.secret_key_distr());
        params
            .secret_key_sampler()
            .sample_signed_to(&mut secret_key.key, rng);
        secret_key
    }
}
