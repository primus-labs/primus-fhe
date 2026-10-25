//! Exact explicit-modulus NTT NTRU secret key.

use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::NttPolynomialOwned;
use primus_reduce::{ExplicitModulus, FieldContext};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    NtruEncryptionParameters, NtruError, SecretKeyDistr, parameter::KEY_GENERATION_ATTEMPTS,
};

use super::NtruSecretKey;

mod decrypt;
mod encrypt;
mod gadget;
mod message;
mod workspace;

pub use workspace::NttNtruGadgetEncryptWorkspace;

/// An NTRU secret key represented by `NTT(f)` and its exact pointwise inverse.
/// Both polynomials are securely erased on drop, including failed conversions.
/// The explicit coefficient modulus is recorded during conversion or generation;
/// no transform table is retained. Explicit [`Zeroize::zeroize`] clears both
/// polynomials, preserving only the public distribution and modulus metadata.
/// The erased key must be discarded.
///
/// # Correctness
///
/// Public operations check the recorded modulus and layout, but cannot establish
/// secret identity, NTT roots or evaluation order. Callers must preserve the
/// construction-time NTT representation.
#[derive(Clone)]
pub struct NttNtruSecretKey<T: FheUint> {
    key: NttPolynomialOwned<T>,
    inv_key: NttPolynomialOwned<T>,
    distr: SecretKeyDistr,
    cipher_modulus: T,
}

impl<T: FheUint> Zeroize for NttNtruSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.0.zeroize();
        self.inv_key.0.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for NttNtruSecretKey<T> {}

impl<T: FheUint> Drop for NttNtruSecretKey<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: FheUint> NttNtruSecretKey<T> {
    /// Protects both buffers before conversion or rejection sampling can fail.
    /// Every candidate and its inverse use the same validated modulus/table.
    fn allocate(poly_length: usize, distr: SecretKeyDistr, cipher_modulus: T) -> Self {
        Self {
            key: NttPolynomialOwned::zero(poly_length),
            inv_key: NttPolynomialOwned::zero(poly_length),
            distr,
            cipher_modulus,
        }
    }

    /// Returns the polynomial length.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.key.as_ref().len()
    }

    /// Returns the proposal distribution before backend rejection sampling.
    #[must_use]
    #[inline]
    pub fn distr(&self) -> SecretKeyDistr {
        self.distr
    }

    /// Returns the explicit modulus shared by `NTT(f)` and its pointwise inverse.
    /// This does not identify a particular secret or NTT representation.
    #[must_use]
    #[inline]
    pub fn cipher_modulus(&self) -> T {
        self.cipher_modulus
    }

    /// Converts a coefficient key to NTT form and computes `NTT(f)^(-1)`.
    ///
    /// # Correctness
    ///
    /// Every coefficient must have unsigned magnitude strictly less than
    /// `modulus.value()`. Conversion uses [`EncodeSigned`](primus_reduce::EncodeSigned),
    /// without general reduction. Keys generated from matching [`NtruEncryptionParameters`] satisfy this
    /// bound; callers importing keys or changing moduli must establish it.
    ///
    /// # Errors
    ///
    /// Returns [`NtruError::NonInvertibleSecretKey`] if an NTT evaluation of
    /// `f` is not invertible modulo `modulus`.
    ///
    /// # Panics
    ///
    /// Panics if the table length differs from the coefficient key length or
    /// its modulus differs from `modulus`.
    pub fn try_from_coeff_secret_key<M, Table>(
        secret_key: &NtruSecretKey<T>,
        modulus: M,
        ntt_table: &Table,
    ) -> Result<Self, NtruError>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let poly_length = secret_key.poly_length();
        assert_eq!(
            ntt_table.poly_length().get(),
            poly_length,
            "NTT polynomial length mismatch"
        );
        assert_eq!(
            ntt_table.modulus(),
            modulus.value(),
            "NTT ciphertext modulus mismatch"
        );

        // Establish drop protection before encoding or inversion can fail.
        let mut transformed = Self::allocate(poly_length, secret_key.distr(), modulus.value());
        transformed.try_update_from_coeff_secret_key(secret_key, modulus, ntt_table)?;
        Ok(transformed)
    }

    /// Overwrites both buffers after the caller establishes matching lengths,
    /// modulus/table and coefficient bounds. A failed inverse may leave partial
    /// output; it stays private until a later successful attempt overwrites it.
    fn try_update_from_coeff_secret_key<M, Table>(
        &mut self,
        secret_key: &NtruSecretKey<T>,
        modulus: M,
        ntt_table: &Table,
    ) -> Result<(), NtruError>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        modulus.encode_signed_slice_to(secret_key.as_slice(), self.key.as_mut());
        ntt_table.transform_slice(self.key.as_mut());

        self.key
            .try_inv_to(&mut self.inv_key, modulus)
            .map_err(|_| NtruError::NonInvertibleSecretKey)?;

        debug_assert!(
            self.key
                .as_ref()
                .iter()
                .zip(self.inv_key.as_ref())
                .all(|(&value, &inverse)| modulus.reduce_mul(value, inverse) == T::ONE)
        );

        Ok(())
    }

    /// Rejection-samples an invertible coefficient key and converts it to NTT
    /// form.
    /// See [`Self::generate_pair`] for error and panic conditions.
    pub fn generate<M, Table, R>(
        params: &NtruEncryptionParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> Result<Self, NtruError>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        Self::generate_pair(params, ntt_table, rng).map(|(_, transformed_key)| transformed_key)
    }

    /// Rejection-samples an invertible key and returns its signed coefficient
    /// and NTT representations. Acceptance requires every NTT evaluation to be nonzero.
    ///
    /// Secret buffers are allocated once, reused across rejected candidates,
    /// and erased on drop, including exhausted searches and unwinding. Returns
    /// the first accepted candidate within 1024 attempts; its distribution is
    /// the proposal conditioned on backend acceptance. [`NtruSecretKey::distr`]
    /// records the proposal, not this conditioning.
    ///
    /// # Errors
    ///
    /// Returns [`NtruError::KeyGenerationExhausted`] if no acceptable key is
    /// found within the bounded search.
    ///
    /// # Panics
    ///
    /// Panics if the NTT table length or modulus differs from the parameters.
    pub fn generate_pair<M, Table, R>(
        params: &NtruEncryptionParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> Result<(NtruSecretKey<T>, Self), NtruError>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        assert_eq!(ntt_table.poly_length().get(), params.poly_length().get());
        assert_eq!(ntt_table.modulus(), params.cipher_modulus().value());

        let mut coefficient_key =
            NtruSecretKey::allocate(params.poly_length().get(), params.secret_key_distr());
        let mut transformed = Self::allocate(
            params.poly_length().get(),
            params.secret_key_distr(),
            params.cipher_modulus().value(),
        );
        let sampler = params.secret_key_sampler();
        for _ in 0..KEY_GENERATION_ATTEMPTS {
            sampler.sample_signed_to(&mut coefficient_key.key, rng);
            match transformed.try_update_from_coeff_secret_key(
                &coefficient_key,
                params.cipher_modulus(),
                ntt_table,
            ) {
                Ok(()) => return Ok((coefficient_key, transformed)),
                Err(NtruError::NonInvertibleSecretKey) => {}
                Err(error) => return Err(error),
            }
        }
        Err(NtruError::KeyGenerationExhausted)
    }

    /// Checks ordinary and gadget parameters once before entering encryption kernels.
    fn assert_domain<M, Table>(&self, params: &NtruEncryptionParameters<T, M>, ntt_table: &Table)
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(
            params.poly_length().get(),
            self.poly_length(),
            "NTRU parameter length mismatch"
        );
        self.assert_ntt_compatible(params.cipher_modulus(), ntt_table);
    }

    /// Checks the owning key, arithmetic modulus and table at an operation boundary.
    /// Encryption levels and batches inherit this domain without rechecking it.
    #[inline]
    fn assert_ntt_compatible(
        &self,
        modulus: impl ExplicitModulus<ValueT = T>,
        ntt_table: &impl NttTable<ValueT = T>,
    ) {
        assert_eq!(
            self.cipher_modulus,
            modulus.value(),
            "NTT NTRU secret-key ciphertext modulus mismatch"
        );
        assert_eq!(
            ntt_table.modulus(),
            self.cipher_modulus,
            "NTT ciphertext modulus mismatch"
        );
        assert_eq!(
            ntt_table.poly_length().get(),
            self.poly_length(),
            "NTT polynomial length mismatch"
        );
    }
}
