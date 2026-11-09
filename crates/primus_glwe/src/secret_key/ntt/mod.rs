//! Single-modulus NTT-domain GLWE secret key with encryption and decryption.

use primus_integer::FheUint;
use primus_lattice::GlweDimension;
use primus_lattice::GlweSize;
use primus_modulus::UintModulus;
use primus_ntt::NttTable;
use primus_poly::NttPolynomialIter;
use primus_reduce::{EncodeSigned, ExplicitModulus, FieldContext};
use primus_shape::PolyLength;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{GlweEncryptionParameters, SecretKeyDistr};

use super::GlweSecretKey;

mod batch;
mod coefficient;
mod decrypt;
mod encrypt;
mod gadget;
mod message;
mod workspace;
pub use workspace::NttGlweGadgetEncryptWorkspace;

/// A single-modulus GLWE secret key in NTT form.
/// Key storage is securely erased on drop. The explicit coefficient modulus is
/// recorded at import or conversion; no transform table is retained.
/// Explicit [`Zeroize::zeroize`] clears the coefficients and leaves the public
/// layout, distribution and modulus metadata. The erased key must be discarded.
///
/// # Correctness
///
/// Key values must be canonical residues in the NTT representation used by
/// subsequent operations. Public operations check the recorded modulus and
/// layout, but cannot establish secret identity, NTT roots or evaluation order.
/// Callers must preserve the construction-time NTT representation.
#[derive(Clone)]
pub struct NttGlweSecretKey<T: FheUint> {
    key: Vec<T>,
    size: GlweSize,
    distr: SecretKeyDistr,
    cipher_modulus: T,
}

impl<T: FheUint> Zeroize for NttGlweSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for NttGlweSecretKey<T> {}

impl<T: FheUint> Drop for NttGlweSecretKey<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: FheUint> NttGlweSecretKey<T> {
    /// Creates a new [`NttGlweSecretKey<T>`].
    ///
    /// # Correctness
    ///
    /// `key` must contain canonical NTT residues under `modulus` and encode
    /// a secret key with distribution `distr` in the representation required by
    /// [`Self`]. These properties are not checked or inferred from the values.
    ///
    /// # Panics
    ///
    /// Panics if `key.len()` differs from `size.mask_len()`. The consumed secret
    /// storage is erased on that failure.
    #[inline]
    #[must_use]
    pub fn new(
        key: Vec<T>,
        size: GlweSize,
        distr: SecretKeyDistr,
        modulus: impl ExplicitModulus<ValueT = T>,
    ) -> Self {
        let secret = Self {
            key,
            size,
            distr,
            cipher_modulus: modulus.value(),
        };
        assert_eq!(
            secret.key.len(),
            size.mask_len(),
            "NTT secret key layout mismatch"
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

    /// Returns the explicit modulus recorded at import or conversion.
    /// This does not identify a particular secret or NTT representation.
    #[must_use]
    #[inline]
    pub fn cipher_modulus(&self) -> T {
        self.cipher_modulus
    }

    /// Iterates over the NTT-domain secret polynomials in GLWE component order.
    /// The raw polynomial views do not carry the owning key's modulus metadata.
    #[must_use]
    #[inline]
    pub fn iter(&self) -> NttPolynomialIter<'_, T> {
        NttPolynomialIter::new(self.key.as_slice(), self.size.poly_length().get())
    }

    /// Encodes and transforms a signed coefficient-domain secret key.
    ///
    /// # Correctness
    ///
    /// Every signed coefficient in `secret_key` must satisfy `s.unsigned_abs() < q`,
    /// where `q` is `ntt_table.modulus()`; see [`EncodeSigned::encode_signed`].
    ///
    /// # Panics
    ///
    /// Panics if the table polynomial length differs from the key layout.
    #[inline]
    #[must_use]
    pub fn from_coeff_secret_key<Table>(secret_key: &GlweSecretKey<T>, ntt_table: &Table) -> Self
    where
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(ntt_table.poly_length(), secret_key.poly_length());
        Self::from_coeff_secret_key_kernel(secret_key, ntt_table)
    }

    /// Requires a matching table length and signed coefficient magnitudes below
    /// its modulus. The final key owns storage before NTT can panic.
    fn from_coeff_secret_key_kernel<Table>(secret_key: &GlweSecretKey<T>, ntt_table: &Table) -> Self
    where
        Table: NttTable<ValueT = T>,
    {
        let size = secret_key.glwe_size();
        let poly_length = size.poly_length().get();
        let mut key = Self {
            key: vec![T::ZERO; size.mask_len()],
            size,
            distr: secret_key.distr(),
            cipher_modulus: ntt_table.modulus(),
        };
        let modulus = UintModulus(ntt_table.modulus());
        for (coefficients, secret) in secret_key.iter().zip(key.key.chunks_exact_mut(poly_length)) {
            modulus.encode_signed_slice_to(coefficients, secret);
            ntt_table.transform_slice(secret);
        }

        key
    }

    /// Samples one signed coefficient key and returns it with its NTT form.
    /// The layout comes from `size`; no plaintext codec is needed.
    /// Fixed weights apply to the complete `k * N` coefficient key. Both
    /// representations are erased on drop, including unwinding during generation.
    ///
    /// # Panics
    ///
    /// Panics before sampling if the table length or modulus differs from
    /// `size` or `params`, respectively.
    /// Inherits [`GlweSecretKey::generate`]'s sampling conditions.
    #[must_use]
    pub fn generate_pair<R, M>(
        size: GlweSize,
        params: &GlweEncryptionParameters<T, M>,
        ntt_table: &impl NttTable<ValueT = T>,
        rng: &mut R,
    ) -> (GlweSecretKey<T>, Self)
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
    {
        assert_eq!(
            ntt_table.poly_length().get(),
            size.poly_length().get(),
            "NTT polynomial length mismatch"
        );
        assert_eq!(
            ntt_table.modulus(),
            params.cipher_modulus().value(),
            "NTT ciphertext modulus mismatch"
        );
        let coefficients = GlweSecretKey::generate(size, params.secret_key_sampler(), rng);
        let key = Self::from_coeff_secret_key_kernel(&coefficients, ntt_table);
        (coefficients, key)
    }

    /// Checks the key, arithmetic modulus and table at an owning operation boundary.
    /// Inner encryption/gadget kernels inherit these conditions without rechecking.
    #[inline]
    fn assert_ntt_compatible(
        &self,
        modulus: impl ExplicitModulus<ValueT = T>,
        ntt_table: &impl NttTable<ValueT = T>,
    ) {
        assert_eq!(
            self.cipher_modulus,
            modulus.value(),
            "NTT GLWE secret-key ciphertext modulus mismatch"
        );
        assert_eq!(
            ntt_table.modulus(),
            self.cipher_modulus,
            "NTT ciphertext modulus mismatch"
        );
        assert_eq!(
            ntt_table.poly_length(),
            self.poly_length(),
            "NTT polynomial length mismatch"
        );
    }
}
