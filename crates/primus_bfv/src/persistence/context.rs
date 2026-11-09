//! Canonical BFV context description and public-object binding.
use primus_glwe_rns::persistence::{
    PublicContextDescription, PublicObjectError as Error, PublicObjectLimits as Limits,
    PublicObjectReader as Reader, PublicObjectWriter as Writer, ntt_fingerprint,
};
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;

use crate::{BfvContext, BfvParameters};

const SCHEME: u64 = 1;

impl BfvContext {
    /// Borrows the canonical public context description, computed once per owner.
    /// The description stores the complete public sampler laws and actual NTT
    /// digest, without secret data, local identity or prepared tables.
    #[must_use]
    pub fn public_bytes(&self) -> &[u8] {
        self.public_descriptor
            .get_or_init(|| self.encode_public_context(ntt_fingerprint(self.table())))
    }

    /// Returns an owned copy of the canonical public context description.
    #[must_use]
    pub fn to_public_bytes(&self) -> Vec<u8> {
        self.public_bytes().to_vec()
    }

    fn encode_public_context(&self, ntt_digest: [u8; 32]) -> Vec<u8> {
        let mut writer = Writer::new(SCHEME, 0);
        writer.usize(self.parameters().poly_length().get());
        writer.u64(self.parameters().codec().t());
        writer.u64(self.parameters().codec().gamma());
        let sampling = self.parameters().encryption_parameters();
        PublicContextDescription {
            levels: self.level_count(),
            moduli: self.parameters().base_q().moduli_values(),
            secret: sampling.secret_key_distr(),
            error: sampling.noise_distribution().distribution(),
            ntt_digest,
        }
        .write(&mut writer);
        writer.finish()
    }

    /// Restores a fresh local context after bounded, exact public-format validation.
    ///
    /// # Errors
    /// Rejects format/version, lengths, nonprime ordered Q, unsupported samplers,
    /// resource budgets, trailing bytes or a different actual NTT representation.
    /// Arithmetic construction does not establish an RLWE security level.
    pub fn from_public_bytes(bytes: &[u8], limits: Limits) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes, SCHEME, 0, limits)?;
        let n = reader.usize(limits.max_poly_length)?;
        let length = PolyLength::try_new(n).map_err(Error::parameters)?;
        let plaintext = reader.u64()?;
        let gamma = reader.u64()?;
        let description = PublicContextDescription::read(reader, length)?;
        let parameters = BfvParameters::try_with_owned_moduli(
            length,
            BarrettModulus::try_new(plaintext).ok_or(Error::Malformed("plaintext modulus"))?,
            BarrettModulus::try_new(gamma).ok_or(Error::Malformed("decoder modulus"))?,
            description.moduli,
            description.secret,
            description.error,
        )
        .map_err(Error::parameters)?;
        let context =
            Self::try_with_levels(parameters, description.levels).map_err(Error::parameters)?;
        if ntt_fingerprint(context.table()) != description.ntt_digest {
            return Err(Error::Binding);
        }
        let _ = context
            .public_descriptor
            .set(context.encode_public_context(description.ntt_digest));
        Ok(context)
    }

    pub(crate) fn public_writer(&self, role: u64) -> Writer {
        let mut writer = Writer::new(SCHEME, role);
        writer.blob(self.public_bytes());
        writer
    }

    pub(crate) fn public_reader<'a>(
        &self,
        bytes: &'a [u8],
        role: u64,
        limits: Limits,
    ) -> Result<Reader<'a>, Error> {
        let mut reader = Reader::new(bytes, SCHEME, role, limits)?;
        if self.parameters().poly_length().get() > limits.max_poly_length
            || self.parameters().base_q().moduli_count() > limits.max_moduli
        {
            return Err(Error::Limit("context geometry"));
        }
        if reader.blob()? != self.public_bytes() {
            return Err(Error::Binding);
        }
        Ok(reader)
    }
}
