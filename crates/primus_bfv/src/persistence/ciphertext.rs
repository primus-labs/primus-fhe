//! Native BFV ciphertext storage and receiver-local adoption.
use primus_data::Data;
use primus_glwe_rns::persistence::{
    PublicObjectError as Error, PublicObjectLimits as Limits, decode_public_words,
};

use crate::{BfvCiphertext, BfvContext};

impl BfvContext {
    /// Encodes a complete canonical ciphertext together with its context and level.
    /// # Errors
    /// Rejects an unavailable level, foreign binding, incomplete storage or residue.
    pub fn export_ciphertext<D: Data<Elem = u64>>(
        &self,
        input: &BfvCiphertext<D>,
        level: usize,
    ) -> Result<Vec<u8>, Error> {
        self.validate_canonical_ciphertext(input, level)
            .map_err(Error::parameters)?;
        let mut writer = self.public_writer(1);
        writer.usize(level);
        writer.words(input.as_ref());
        Ok(writer.finish())
    }

    /// Restores a ciphertext with this receiver's local context/level binding.
    /// # Errors
    /// Rejects wrong context/NTT, malformed canonical storage or trailing bytes.
    /// A declared secret/message relation is not authenticated by this operation.
    pub fn import_ciphertext(
        &self,
        bytes: &[u8],
        limits: Limits,
    ) -> Result<BfvCiphertext<Vec<u64>>, Error> {
        let mut reader = self.public_reader(bytes, 1, limits)?;
        let level = reader.usize(self.level_count() - 1)?;
        let data = reader.canonical_bytes(
            2 * self.rns_poly_len(level),
            self.parameters().poly_length().get(),
            self.codec(level).moduli_values(),
        )?;
        reader.finish()?;
        Ok(BfvCiphertext::bound(decode_public_words(data), self, level))
    }
}
