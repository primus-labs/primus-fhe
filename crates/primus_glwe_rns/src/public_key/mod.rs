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
use crate::{
    CrtGlweEncryptionParameters, DcrtGadgetDomain, DcrtGlweDomain, DcrtGlweSecretKey,
    RnsDomainError,
};

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

    /// Generates a public key from codec-free sampling state and its ordered Q base.
    /// The zero encryption needs neither a plaintext modulus nor BFV recovery data.
    ///
    /// # Panics
    /// Panics if the parameters/table/key layouts or ordered moduli differ,
    /// before consuming randomness.
    ///
    /// # Correctness
    /// The secret key and table must use the same NTT representation.
    pub fn new<Table, R, M>(
        secret_key: &DcrtGlweSecretKey<T>,
        parameters: &CrtGlweEncryptionParameters<T>,
        base_q: &RNSBase<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) -> Self
    where
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
    {
        DcrtGlweDomain::try_new(parameters, base_q, table)
            .expect("public-key sampling parameters and table are incompatible");
        secret_key
            .validate_parameters(parameters.size(), base_q.moduli())
            .expect("public-key secret and parameters are incompatible");
        let size = parameters.size();
        let poly_length = size.poly_length().get();
        let mut data = DcrtGlwe::zero(size.rns_glwe_len());
        let (mask, mut body) = data.a_b_mut(size.rns_poly_len());
        parameters.sample_noise_to(body.as_mut(), base_q.moduli_values(), rng);
        table.transform_slice(body.as_mut());
        for (secret, polynomial) in secret_key.iter_dcrt_poly().zip(mask) {
            primus_distr::sample_crt_uniform_values_to(
                polynomial.0,
                poly_length,
                parameters.cipher_moduli_uniform_distr(),
                rng,
            );
            body.add_mul_assign(&polynomial, &secret, poly_length, base_q.moduli());
        }
        Self {
            key: data,
            size,
            moduli: base_q.moduli_values().to_vec(),
        }
    }

    /// Binds a codec-free domain and allocates one reusable ephemeral polynomial.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] if the key layout or ordered basis differs.
    pub fn try_bind_raw<'a, M, Table>(
        &'a self,
        domain: &DcrtGlweDomain<'a, T, M, Table>,
    ) -> Result<DcrtGlweRawPublicKeyEncryptor<'a, T, M, Table>, RnsDomainError<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let resources = PublicEncryptionResources::try_new(
            self,
            domain.parameters(),
            domain.rns_base(),
            domain.table(),
        )?;
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
        domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    ) -> Result<DcrtGgswEncryptor<'a, T, M, Table>, RnsDomainError<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let resources = PublicEncryptionResources::try_new(
            self,
            domain.parameters().encryption_parameters(),
            domain.rns_base(),
            domain.table(),
        )?;
        let workspace = DcrtGlwePublicKeyWorkspace::new(resources.size());
        Ok(DcrtGgswEncryptor {
            resources,
            domain,
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
