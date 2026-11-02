//! DCRT secret ownership and numerical resource bindings.

mod conversion;
mod gadget;
mod raw;

use primus_integer::FheUint;
use primus_lattice::RnsGlweSize;
use primus_ntt::NttTable;
use primus_poly::DcrtPolynomialIter;
use primus_reduce::FieldContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::parameter::{validate_glwe_size, validate_moduli};
use crate::{DcrtGadgetDomain, RnsDomainError, SecretKeyDistr};

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

    /// Binds this key to a checked gadget domain before encrypting GLev entries.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] for an incompatible layout or ordered basis.
    pub fn try_bind_gadget<'a, M, Table>(
        &'a self,
        domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    ) -> Result<DcrtGlevEncryptor<'a, T, M, Table>, RnsDomainError<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        self.validate_parameters(
            domain.size().rns_glwe_size(),
            domain.parameters().cipher_moduli(),
        )?;
        Ok(DcrtGlevEncryptor { key: self, domain })
    }

    /// Checks the owned key geometry and modulus order at resource binding.
    pub(crate) fn validate_parameters<M: FieldContext<T>>(
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

/// A secret key bound to one checked GLev encryption domain.
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
    domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
}
