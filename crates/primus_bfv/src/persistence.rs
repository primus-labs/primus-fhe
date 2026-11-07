//! Versioned public storage, independent of protocol round payloads.
use crate::{BfvCiphertext, BfvContext, BfvParameters};
use primus_data::Data;
use primus_glwe_rns::persistence::{
    PublicObjectError as Error, PublicObjectLimits as Limits, PublicObjectReader as Reader,
    PublicObjectWriter as Writer, decode_public_words, ntt_fingerprint, read_sampling,
    write_sampling,
};
use primus_glwe_rns::rlwe_parameters::validate_ntt_primes;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;

const SCHEME: u64 = 1;

impl BfvContext {
    /// Encodes all public parameters, sampler laws, prepared levels and actual NTT roots.
    /// No secret, local binding pointer or sampler table is serialized.
    #[must_use]
    pub fn to_public_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new(SCHEME, 0);
        writer.usize(self.parameters().poly_length().get());
        writer.u64(self.parameters().codec().t());
        writer.u64(self.parameters().codec().gamma());
        writer.usize(self.level_count());
        writer.words(self.parameters().codec().moduli_values());
        let sampling = self.parameters().encryption_parameters();
        write_sampling(
            &mut writer,
            sampling.secret_key_distr(),
            sampling.noise_distribution().distribution(),
        );
        writer.digest(
            self.public_ntt_digest
                .get_or_init(|| ntt_fingerprint(self.table())),
        );
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
        let levels = reader.usize(limits.max_moduli)?;
        let primes = reader.words(limits.max_moduli)?;
        let (secret, error) = read_sampling(&mut reader, n, limits)?;
        let digest = reader.digest()?;
        reader.finish()?;
        limits.context_with_sampling(n, primes.len(), levels, secret, error)?;
        validate_ntt_primes(n, &primes).map_err(Error::parameters)?;
        let moduli = primes
            .into_iter()
            .map(|q| BarrettModulus::try_new(q).ok_or(Error::Malformed("Q modulus")))
            .collect::<Result<Vec<_>, _>>()?;
        let parameters = BfvParameters::try_with_decoder_modulus(
            length,
            BarrettModulus::try_new(plaintext).ok_or(Error::Malformed("plaintext modulus"))?,
            BarrettModulus::try_new(gamma).ok_or(Error::Malformed("decoder modulus"))?,
            &moduli,
            secret,
            error,
        )
        .map_err(Error::parameters)?;
        let context = Self::try_with_levels(parameters, levels).map_err(Error::parameters)?;
        if ntt_fingerprint(context.table()) != digest {
            return Err(Error::Binding);
        }
        let _ = context.public_ntt_digest.set(digest);
        Ok(context)
    }

    /// Encodes a complete canonical ciphertext together with its context and level.
    /// BGV storage additionally carries its actual message correction factor.
    /// # Errors
    /// Rejects an unavailable level, foreign binding, incomplete storage or residue.
    pub fn export_ciphertext<D: Data<Elem = u64>>(
        &self,
        input: &BfvCiphertext<D>,
        level: usize,
    ) -> Result<Vec<u8>, Error> {
        self.public_level(level)?;
        self.check_ciphertext(input, level)
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
            self.parameters()
                .codec()
                .moduli_values()
                .get(..self.parameters().codec().base_q().moduli_count() - level)
                .ok_or(Error::Malformed("level"))?,
        )?;
        reader.finish()?;
        Ok(BfvCiphertext::bound(decode_public_words(data), self, level))
    }

    pub(crate) fn public_level(&self, level: usize) -> Result<(), Error> {
        if level >= self.level_count() {
            return Err(Error::Malformed("unprepared level"));
        }
        Ok(())
    }
    pub(crate) fn public_writer(&self, role: u64) -> Writer {
        let mut writer = Writer::new(SCHEME, role);
        writer.blob(&self.to_public_bytes());
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
        if reader.blob()? != self.to_public_bytes() {
            return Err(Error::Binding);
        }
        Ok(reader)
    }
}
