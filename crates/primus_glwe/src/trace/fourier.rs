//! Trace keys for coefficient-domain native-torus ciphertexts.

use crate::{
    FourierGlweAutomorphismKey, FourierGlweAutomorphismWorkspace, FourierGlweEncryptor,
    GlevParameters, GlweSize,
};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_lattice::glwe::Glwe;
use primus_modulus::NativeModulus;

/// Reusable workspace for Fourier-key trace and coefficient projection.
pub struct FourierGlweTraceWorkspace<T: TorusFftValue> {
    pub(super) automorphism_output: Glwe<Vec<T>>,
    pub(super) automorphism: FourierGlweAutomorphismWorkspace<T>,
}
impl<T: TorusFftValue> FourierGlweTraceWorkspace<T> {
    /// Allocates workspace for one immutable GLWE layout.
    #[must_use]
    pub fn new(size: GlweSize) -> Self {
        Self {
            automorphism_output: Glwe::zero(size.glwe_len()),
            automorphism: FourierGlweAutomorphismWorkspace::new(size),
        }
    }
}

/// Owns the log2(N) automorphism keys shared by trace, projection and packing.
/// All ciphertext inputs/outputs are coefficient-domain native-torus GLWEs.
#[derive(Clone)]
pub struct FourierGlweTraceKey<T: TorusFftValue> {
    pub(super) automorphism_keys: Vec<FourierGlweAutomorphismKey<T>>,
    pub(super) glwe_size: GlweSize,
}
impl<T: TorusFftValue> FourierGlweTraceKey<T> {
    /// Generates keys for degrees N+1,N/2+1,...,3. Inherits the key consistency,
    /// layout and FFT requirements of [`FourierGlweAutomorphismKey::generate`].
    ///
    /// # Panics
    /// Panics if key, parameter or FFT layouts differ.
    /// Shared compatibility checks precede sampling any automorphism key.
    #[must_use]
    pub fn generate<Table: FftTable, R: rand::Rng + rand::CryptoRng>(
        encryptor: &mut FourierGlweEncryptor<'_, T>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> Self {
        encryptor.assert_gadget_compatible(params, fft);

        let glwe_size = encryptor.glwe_size();
        let automorphism_keys = (1..=glwe_size.poly_length().log_n())
            .rev()
            .map(|shift| {
                FourierGlweAutomorphismKey::generate_kernel(
                    (1 << shift) + 1,
                    encryptor,
                    params,
                    fft,
                    rng,
                )
            })
            .collect();
        Self {
            automorphism_keys,
            glwe_size,
        }
    }
    /// Returns the number of available automorphism keys.
    #[must_use]
    pub fn automorphism_count(&self) -> usize {
        self.automorphism_keys.len()
    }
    /// Returns the decomposition basis shared by the keys.
    #[must_use]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        self.automorphism_keys[0].basis()
    }
}
