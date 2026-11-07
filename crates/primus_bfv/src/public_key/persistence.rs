//! Checked public-key storage under a receiver's native numerical context.
use super::*;
use crate::BfvContext;
use primus_glwe_rns::persistence::{
    PublicObjectError as Error, PublicObjectLimits as Limits, decode_public_words,
};
impl BfvContext {
    /// Encodes a public zero-encryption key, preserving the exact native context.
    /// # Errors
    /// Rejects a foreign owner, incomplete storage or noncanonical residues.
    pub fn export_public_key(&self, key: &BfvPublicKey) -> Result<Vec<u8>, Error> {
        self.check_ciphertext(&key.ciphertext, 0)
            .map_err(Error::parameters)?;
        let mut writer = self.public_writer(2);
        writer.words(key.ciphertext.as_ref());
        Ok(writer.finish())
    }
    /// Checks public-key geometry and restores a new local binding without secrets.
    /// # Errors
    /// Rejects wrong context/role/NTT, byte/word caps, noncanonical or trailing data.
    /// A structurally valid public key need not be honestly generated or authenticated.
    pub fn import_public_key(&self, bytes: &[u8], limits: Limits) -> Result<BfvPublicKey, Error> {
        let mut reader = self.public_reader(bytes, 2, limits)?;
        let data = reader.canonical_bytes(
            2 * self.rns_poly_len(0),
            self.parameters().poly_length().get(),
            self.parameters().codec().moduli_values(),
        )?;
        reader.finish()?;
        Ok(BfvPublicKey::from_collective(
            self,
            decode_public_words(data),
        ))
    }
}
