//! DCRT secret ownership and numerical resource bindings.

mod conversion;
mod gadget;
mod raw;

use primus_integer::FheUint;
use primus_lattice::RnsGlweSize;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::DcrtPolynomialIter;
use primus_reduce::FieldContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::parameter::{validate_dcrt_table, validate_glwe_size, validate_moduli};
use crate::{CrtGlevParameters, CrtGlweEncryptionParameters, RnsDomainError, SecretKeyDistr};

pub use raw::DcrtGlweRawSecretKeyContext;

/// A GLWE secret key represented in NTT form for every ordered RNS modulus.
/// Key storage is securely erased on drop.
#[derive(Clone)]
pub struct DcrtGlweSecretKey<T: FheUint> {
    key: Vec<T>,
    distr: SecretKeyDistr,
    size: RnsGlweSize,
    moduli: Vec<T>,
}

impl<T: FheUint> Zeroize for DcrtGlweSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for DcrtGlweSecretKey<T> {}

impl<T: FheUint> Drop for DcrtGlweSecretKey<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: FheUint> DcrtGlweSecretKey<T> {
    pub(crate) fn key(&self) -> &[T] {
        &self.key
    }

    /// Returns the secret-key distribution.
    #[must_use]
    pub fn distr(&self) -> SecretKeyDistr {
        self.distr
    }

    /// Returns the RNS GLWE layout of this secret key.
    #[inline]
    #[must_use]
    pub fn rns_glwe_size(&self) -> RnsGlweSize {
        self.size
    }

    /// Iterates over the DCRT secret polynomials in GLWE component order.
    #[must_use]
    pub fn iter_dcrt_poly(&self) -> DcrtPolynomialIter<'_, T> {
        DcrtPolynomialIter::new(self.key.as_slice(), self.size.rns_poly_len())
    }

    /// Binds gadget arithmetic, sampling state and transforms for GLev encryption.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] for an incompatible layout or ordered basis.
    pub fn try_bind_gadget<'a, M, Table>(
        &'a self,
        parameters: &'a CrtGlevParameters<T, M>,
        sampling_parameters: &'a CrtGlweEncryptionParameters<T>,
        table: &'a DcrtTable<Table>,
    ) -> Result<DcrtGlevEncryptor<'a, T, M, Table>, RnsDomainError<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        validate_glwe_size(
            parameters.size().rns_glwe_size(),
            sampling_parameters.size(),
        )?;
        sampling_parameters.validate_base(parameters.base_q())?;
        validate_dcrt_table(parameters.poly_length(), parameters.cipher_moduli(), table)?;
        self.validate_parameters(
            parameters.size().rns_glwe_size(),
            parameters.cipher_moduli(),
        )?;
        Ok(DcrtGlevEncryptor {
            key: self,
            parameters,
            sampling_parameters,
            table,
        })
    }

    /// Checks this key's complete geometry and ordered numerical modulus basis.
    ///
    /// Scheme-specific resource owners can validate the key without constructing
    /// an encryption context. No key data is cloned or transformed.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] for a layout or ordered modulus mismatch.
    /// Matching moduli do not establish NTT roots, evaluation order or secret
    /// identity; consumers must uphold those representation requirements.
    pub fn validate_parameters<M: FieldContext<T>>(
        &self,
        size: RnsGlweSize,
        moduli: &[M],
    ) -> Result<(), RnsDomainError<T>> {
        validate_glwe_size(size, self.size)?;
        validate_moduli(
            self.moduli.iter().copied(),
            moduli.iter().map(|m| m.value()),
        )
    }
}

/// A secret key bound to the arithmetic and sampling resources for GLev encryption.
///
/// Construct with [`DcrtGlweSecretKey::try_bind_gadget`] and reuse across
/// key rows. Full input/output layouts and transform identity remain caller contracts.
pub struct DcrtGlevEncryptor<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    key: &'a DcrtGlweSecretKey<T>,
    parameters: &'a CrtGlevParameters<T, M>,
    sampling_parameters: &'a CrtGlweEncryptionParameters<T>,
    table: &'a DcrtTable<Table>,
}
