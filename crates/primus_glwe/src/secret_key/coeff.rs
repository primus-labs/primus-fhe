//! Single-modulus coefficient-domain GLWE secret key.

use num_traits::ConstZero;
use primus_distr::SecretKeySampler;
use primus_integer::FheUint;
use primus_lattice::GlweDimension;
use primus_lattice::GlweSize;
use primus_shape::PolyLength;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::SecretKeyDistr;

/// A GLWE secret key stored as signed coefficient polynomials.
/// Signed coefficients are securely erased when the key is dropped.
#[derive(Clone)]
pub struct GlweSecretKey<T: FheUint> {
    pub(crate) key: Vec<T::SignedInteger>,
    pub(crate) glwe_size: GlweSize,
    pub(crate) distr: SecretKeyDistr,
}

impl<T: FheUint> Zeroize for GlweSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for GlweSecretKey<T> {}

impl<T: FheUint> Drop for GlweSecretKey<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: FheUint> GlweSecretKey<T> {
    /// Wraps signed coefficient storage with its layout and distribution metadata.
    /// The distribution is recorded without checking the supplied coefficients.
    /// Rejected storage is erased when layout validation unwinds.
    ///
    /// # Panics
    ///
    /// Panics if `key.len()` differs from `glwe_size.mask_len()`.
    #[inline]
    #[must_use]
    pub fn new(key: Vec<T::SignedInteger>, glwe_size: GlweSize, distr: SecretKeyDistr) -> Self {
        // Establish the erasing owner before validation can unwind.
        let secret = Self {
            key,
            glwe_size,
            distr,
        };
        assert_eq!(
            secret.key.len(),
            glwe_size.mask_len(),
            "coefficient secret key layout mismatch"
        );

        secret
    }

    /// Returns the GLWE layout of this [`GlweSecretKey<T>`].
    #[inline]
    #[must_use]
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Returns the coefficient polynomial length.
    #[inline]
    #[must_use]
    pub fn poly_length(&self) -> PolyLength {
        self.glwe_size.poly_length()
    }

    /// Returns the GLWE dimension.
    #[inline]
    #[must_use]
    pub fn dimension(&self) -> GlweDimension {
        self.glwe_size.dimension()
    }

    /// Returns the secret-key distribution.
    #[inline]
    #[must_use]
    pub fn distr(&self) -> SecretKeyDistr {
        self.distr
    }

    /// Returns all coefficient-domain secret-key values.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[T::SignedInteger] {
        &self.key
    }

    /// Iterates over the coefficient-domain secret polynomials.
    #[inline]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &[T::SignedInteger]> + DoubleEndedIterator {
        self.key.chunks_exact(self.glwe_size.poly_length().get())
    }

    /// Generates a canonical signed GLWE secret key using borrowed precomputation.
    /// Fixed weights apply to the complete coefficient key.
    /// Partial secret storage is erased if sampling panics.
    ///
    /// # Panics
    ///
    /// Panics if a fixed weight exceeds `glwe_size.mask_len()` or its sum overflows.
    #[must_use]
    pub fn generate<R>(glwe_size: GlweSize, sampler: &SecretKeySampler<T>, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        // Own the allocation before sampling so unwinding erases partial secrets.
        let mut key = Self {
            key: vec![T::SignedInteger::ZERO; glwe_size.mask_len()],
            glwe_size,
            distr: sampler.distr(),
        };
        sampler.sample_signed_to(&mut key.key, rng);
        key
    }
}
