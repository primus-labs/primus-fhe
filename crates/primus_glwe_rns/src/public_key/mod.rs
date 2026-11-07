//! Public-key ownership, generation and prepared encryption bindings.

mod encryption;
mod gadget;
mod workspace;

pub use encryption::DcrtGlweRawPublicKeyEncryptor;
pub use gadget::DcrtGgswEncryptor;
pub use workspace::DcrtGlwePublicKeyWorkspace;

use primus_integer::FheUint;
use primus_lattice::{RnsGlweSize, glwe::DcrtGlwe};
use primus_ntt::{DcrtTable, NttTable};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use crate::parameter::{validate_glwe_size, validate_moduli};
use crate::{CrtGlevParameters, CrtGlweEncryptionParameters, RnsDomainError};

use encryption::PublicEncryptionResources;

/// A public GLWE encryption key stored in DCRT form.
#[derive(Clone)]
pub struct DcrtGlwePublicKey<T: FheUint> {
    key: DcrtGlwe<Vec<T>>,
    size: RnsGlweSize,
    moduli: Vec<T>,
}

impl<T: FheUint> DcrtGlwePublicKey<T> {
    /// Replaces the public ciphertext data from bytes, retaining its domain metadata.
    ///
    /// # Correctness
    /// The bytes must encode a public key in this key's ordered basis and NTT representation;
    /// the payload does not contain or validate that metadata.
    #[inline]
    pub fn read_bytes(&mut self, data: &[u8]) {
        self.key.read_bytes(data);
    }

    /// Writes this public key's ciphertext data to `data`, excluding domain metadata.
    #[inline]
    pub fn write_bytes(&self, data: &mut [u8]) {
        self.key.write_bytes(data);
    }

    /// Returns the bytes count of this public key, excluding domain metadata.
    #[must_use]
    pub fn byte_count(&self) -> usize {
        self.key.byte_count()
    }

    pub(crate) fn from_zero_encryption(
        key: DcrtGlwe<Vec<T>>,
        size: RnsGlweSize,
        moduli: &[T],
    ) -> Self {
        Self {
            key,
            size,
            moduli: moduli.to_vec(),
        }
    }

    /// Checks codec-free resources, then allocates one reusable ephemeral polynomial.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] if the key layout or ordered basis differs.
    pub fn try_bind_raw<'a, M, Table>(
        &'a self,
        parameters: &'a CrtGlweEncryptionParameters<T>,
        rns_base: &'a RNSBase<T, M>,
        table: &'a DcrtTable<Table>,
    ) -> Result<DcrtGlweRawPublicKeyEncryptor<'a, T, M, Table>, RnsDomainError<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let resources = PublicEncryptionResources::try_new(self, parameters, rns_base, table)?;
        let workspace = DcrtGlwePublicKeyWorkspace::new(resources.size());
        Ok(DcrtGlweRawPublicKeyEncryptor {
            resources,
            workspace,
        })
    }

    /// Binds monomial GGSW encryption and allocates reusable ephemeral scratch.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] for an incompatible layout or ordered basis.
    pub fn try_bind_gadget<'a, M, Table>(
        &'a self,
        parameters: &'a CrtGlevParameters<T, M>,
        sampling_parameters: &'a CrtGlweEncryptionParameters<T>,
        table: &'a DcrtTable<Table>,
    ) -> Result<DcrtGgswEncryptor<'a, T, M, Table>, RnsDomainError<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        validate_glwe_size(
            parameters.size().rns_glwe_size(),
            sampling_parameters.size(),
        )?;
        let resources = PublicEncryptionResources::try_new(
            self,
            sampling_parameters,
            parameters.base_q(),
            table,
        )?;
        let workspace = DcrtGlwePublicKeyWorkspace::new(resources.size());
        Ok(DcrtGgswEncryptor {
            resources,
            parameters,
            workspace,
        })
    }

    fn validate_parameters<M: FieldContext<T>>(
        &self,
        size: RnsGlweSize,
        moduli: &[M],
    ) -> Result<(), RnsDomainError<T>> {
        validate_glwe_size(size, self.size)?;
        validate_moduli(
            self.moduli.iter().copied(),
            moduli.iter().map(|modulus| modulus.value()),
        )
    }
}
