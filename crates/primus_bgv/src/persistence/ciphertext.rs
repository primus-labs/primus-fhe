//! Native BGV ciphertext storage and receiver-local adoption.
use primus_data::Data;
use primus_glwe_rns::persistence::{
    PublicObjectError as Error, PublicObjectLimits as Limits, decode_public_words,
};

use crate::{BgvCiphertext, BgvContext};

impl BgvContext {
    /// Encodes a complete canonical ciphertext together with its context and level.
    /// BGV storage additionally carries its actual message correction factor.
    /// # Errors
    /// Rejects an unavailable level, foreign binding, incomplete storage,
    /// nonunit factor or noncanonical residue.
    pub fn export_ciphertext<D: Data<Elem = u64>>(
        &self,
        input: &BgvCiphertext<D>,
        level: usize,
    ) -> Result<Vec<u8>, Error> {
        self.validate_canonical_ciphertext(input, level)
            .map_err(Error::parameters)?;
        let mut writer = self.public_writer(1);
        writer.usize(level);
        writer.u64(input.correction_factor());
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
    ) -> Result<BgvCiphertext<Vec<u64>>, Error> {
        let mut reader = self.public_reader(bytes, 1, limits)?;
        let level = reader.usize(self.level_count() - 1)?;
        let factor = reader.u64()?;
        self.validate_correction_factor(factor)
            .map_err(Error::parameters)?;
        let data = reader.canonical_bytes(
            2 * self.rns_poly_len(level),
            self.parameters().poly_length().get(),
            self.base_q(level).moduli_values(),
        )?;
        reader.finish()?;
        let mut output = BgvCiphertext::from_bound(decode_public_words(data), self, level);
        output.set_correction_factor(factor);
        Ok(output)
    }
}
