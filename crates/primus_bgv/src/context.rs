use crate::{BgvCiphertext, BgvParameters, BgvPublicKey, BgvPublicKeyEncryptor, BgvPublicKeyError};
use primus_ntt::{NttError, U64DcrtTable};

/// One immutable owner of full-ring BGV parameters and their DCRT NTT table.
/// Clients, evaluators and public encryptors borrow this owner without cloning.
pub struct BgvContext {
    parameters: BgvParameters,
    table: U64DcrtTable,
}

impl BgvContext {
    /// Consumes prepared parameters and checks each full-ring NTT modulus.
    ///
    /// # Correctness
    /// Ciphertext moduli must be prime. Transform preparation checks its numeric
    /// root/size requirements; it does not certify primality. Coefficient p need
    /// not be prime; batching has its own stronger plaintext-field requirements.
    ///
    /// # Errors
    /// Rejects a basis incompatible with the requested full polynomial length.
    pub fn try_new(parameters: BgvParameters) -> Result<Self, NttError<u64>> {
        let table = U64DcrtTable::new(parameters.poly_length(), parameters.base_q().moduli())?;
        Ok(Self { parameters, table })
    }

    /// Borrows the unique parameters and sampler state.
    #[must_use]
    pub fn parameters(&self) -> &BgvParameters {
        &self.parameters
    }

    /// Borrows the full ciphertext-ring transform table.
    #[must_use]
    pub fn table(&self) -> &U64DcrtTable {
        &self.table
    }

    /// Returns the complete modulus-major DCRT polynomial storage length.
    #[must_use]
    pub fn rns_poly_len(&self) -> usize {
        self.parameters.size().rns_poly_len()
    }

    /// Allocates one complete native zeroed ciphertext.
    #[must_use]
    pub fn new_ciphertext(&self) -> BgvCiphertext<Vec<u64>> {
        BgvCiphertext::zero(self.parameters.size().rns_glwe_len())
    }

    /// Binds a native public key and allocates one erasing ephemeral workspace.
    ///
    /// # Errors
    /// Rejects different polynomial geometry, p or ordered Q. Actual secret and
    /// NTT root/evaluation identity remain caller contracts.
    pub fn public_key_encryptor<'a>(
        &'a self,
        key: &'a BgvPublicKey,
    ) -> Result<BgvPublicKeyEncryptor<'a>, BgvPublicKeyError> {
        BgvPublicKeyEncryptor::try_new(key, self)
    }
}
