//! Native-torus Fourier-domain GLWE secret key with encryption and decryption.

use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::SignedInteger;
use primus_lattice::GlweDimension;
use primus_lattice::GlweSize;
use primus_modulus::NativeModulus;
use primus_poly::FourierPolynomialIter;
use primus_shape::PolyLength;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{GlweEncryptionParameters, SecretKeyDistr};

use super::GlweSecretKey;

mod batch;
mod decrypt;
mod encrypt;
mod gadget;
mod message;
mod workspace;
pub use workspace::{
    FourierGlweDecryptWorkspace, FourierGlweEncryptWorkspace, FourierGlweGadgetEncryptWorkspace,
};

/// A native-torus GLWE secret key represented in the Fourier domain.
///
/// Each coefficient-domain secret polynomial is transformed with
/// [`FftTable::forward_as_integer`]. Ciphertext polynomials use torus-scaled
/// Fourier values instead, so their pointwise product has the correct torus
/// scale.
/// Key storage is securely erased on drop. Operations must use the same FFT
/// table instance as the one used to construct this key.
#[derive(Clone)]
pub struct FourierGlweSecretKey {
    key: Vec<Complex64>,
    size: GlweSize,
    distr: SecretKeyDistr,
}

impl Zeroize for FourierGlweSecretKey {
    #[inline]
    fn zeroize(&mut self) {
        for value in &mut self.key {
            value.re.zeroize();
            value.im.zeroize();
        }
        self.key.clear();
        self.key.spare_capacity_mut().zeroize();
    }
}

impl ZeroizeOnDrop for FourierGlweSecretKey {}

impl Drop for FourierGlweSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl FourierGlweSecretKey {
    /// Wraps integer-scaled Fourier secret polynomials.
    /// The values must follow this type's representation contract and the
    /// recorded distribution; raw construction does not check those properties.
    /// Rejected storage is erased when layout validation unwinds.
    ///
    /// # Panics
    ///
    /// Panics if `key.len()` differs from `size.fourier_mask_len()`.
    #[inline]
    #[must_use]
    pub fn new(key: Vec<Complex64>, size: GlweSize, distr: SecretKeyDistr) -> Self {
        // Establish the erasing owner before validation can unwind.
        let secret = Self { key, size, distr };
        assert_eq!(
            secret.key.len(),
            size.fourier_mask_len(),
            "FOURIER secret key layout mismatch"
        );
        secret
    }

    /// Returns the coefficient-domain GLWE layout.
    #[inline]
    #[must_use]
    pub fn glwe_size(&self) -> GlweSize {
        self.size
    }

    /// Returns the coefficient polynomial length.
    #[inline]
    #[must_use]
    pub fn poly_length(&self) -> PolyLength {
        self.size.poly_length()
    }

    /// Returns the GLWE dimension.
    #[inline]
    #[must_use]
    pub fn dimension(&self) -> GlweDimension {
        self.size.dimension()
    }

    /// Returns the secret-key distribution.
    #[inline]
    #[must_use]
    pub fn distr(&self) -> SecretKeyDistr {
        self.distr
    }

    /// Iterates over the Fourier-domain secret polynomials.
    #[inline]
    #[must_use]
    pub fn iter(&self) -> FourierPolynomialIter<'_> {
        FourierPolynomialIter::new(&self.key, self.size.fourier_poly_len())
    }

    /// Converts a native coefficient-domain secret key to Fourier form.
    ///
    /// # Panics
    ///
    /// Panics if the FFT polynomial length differs from the key layout.
    #[must_use]
    pub fn from_coeff_secret_key<T, Table>(
        secret_key: &GlweSecretKey<T>,
        fft: &mut FftEngine<'_, Table>,
    ) -> Self
    where
        T: TorusFftValue,
        Table: FftTable,
    {
        let size = secret_key.glwe_size();
        assert_eq!(size.poly_length().get(), fft.poly_length().get());

        let fourier_length = fft.fourier_length();
        let mut key = Self::new(
            vec![Complex64::default(); size.fourier_mask_len()],
            size,
            secret_key.distr(),
        );
        let mut native_coefficients = Zeroizing::new(vec![T::ZERO; size.poly_length().get()]);
        for (coefficients, fourier) in secret_key
            .iter()
            .zip(key.key.chunks_exact_mut(fourier_length))
        {
            native_coefficients
                .iter_mut()
                .zip(coefficients)
                .for_each(|(output, &coefficient)| {
                    *output = coefficient.cast_to_unsigned();
                });
            fft.forward_as_integer(&native_coefficients, fourier);
        }

        key
    }

    /// Samples one signed coefficient key and returns it with its Fourier form.
    /// The layout comes from `size`; no plaintext codec is needed.
    /// Fixed weights apply to the complete `k * N` coefficient key. Both
    /// representations and conversion scratch are erased on drop, including
    /// unwinding during generation. Keep using the same FFT table instance.
    ///
    /// # Panics
    ///
    /// Panics before sampling if the FFT length differs from `size`.
    /// Inherits [`GlweSecretKey::generate`]'s sampling conditions.
    #[must_use]
    pub fn generate_pair<T, R, Table>(
        size: GlweSize,
        params: &GlweEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> (GlweSecretKey<T>, Self)
    where
        R: rand::Rng + rand::CryptoRng,
        Table: FftTable,
        T: TorusFftValue,
    {
        assert_eq!(
            fft.poly_length().get(),
            size.poly_length().get(),
            "FFT polynomial length mismatch"
        );
        let coefficients = GlweSecretKey::generate(size, params.secret_key_sampler(), rng);
        let key = Self::from_coeff_secret_key(&coefficients, fft);
        (coefficients, key)
    }
}
