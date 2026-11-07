//! Public role-key storage. Actual secrets are never serialized.
use primus_glwe_rns::persistence::{
    DecodedEvaluationKey, EvaluationKeyRole, PublicObjectError as Error,
    PublicObjectLimits as Limits, decode_public_words,
};
use primus_ntt::NttAutomorphismPermutation;

use crate::BgvContext;

use super::{
    backend::NativeEvaluationBasis,
    material::{
        BgvAutomorphismKey, BgvKeySwitchingKey, BgvRelinearizationKey, NativeEvaluationKey,
    },
};

fn encode(
    context: &BgvContext,
    key: &NativeEvaluationKey,
    role: EvaluationKeyRole,
    exponent: usize,
) -> Result<Vec<u8>, Error> {
    key.validate(context).map_err(Error::parameters)?;
    let mut writer = context.public_writer(role as u64);
    writer.usize(key.level);
    writer.usize(exponent);
    match &key.basis {
        NativeEvaluationBasis::Radix(parameters) => writer.write_radix_key(parameters),
        NativeEvaluationBasis::Hybrid(parameters) => writer.write_hybrid_key(parameters),
    }
    writer.words(&key.columns);
    Ok(writer.finish())
}

fn decode(
    context: &BgvContext,
    bytes: &[u8],
    limits: Limits,
    role: EvaluationKeyRole,
) -> Result<(NativeEvaluationKey, usize), Error> {
    let mut reader = context.public_reader(bytes, role as u64, limits)?;
    let level = reader.usize(context.level_count() - 1)?;
    let decoded = DecodedEvaluationKey::read(
        reader,
        role,
        context.parameters().poly_length(),
        context.base_q(level),
    )?;
    let mut key = NativeEvaluationKey::prepare_metadata(context, level, decoded.config)
        .map_err(Error::parameters)?;
    if key.key_len() != decoded.columns.len() / 8 {
        return Err(Error::Malformed("key columns"));
    }
    key.columns = decode_public_words(decoded.columns);
    Ok((key, decoded.exponent))
}

impl BgvContext {
    /// Encodes this typed public role key with its actual level, backend and Q/P.
    /// # Errors
    /// Rejects a key belonging to another local context. Export authenticates nothing.
    pub fn export_relinearization_key(
        &self,
        key: &BgvRelinearizationKey,
    ) -> Result<Vec<u8>, Error> {
        encode(self, &key.key, EvaluationKeyRole::Relinearization, 0)
    }
    /// Restores this typed role under the receiving context after complete validation.
    /// # Errors
    /// Rejects wrong role/context/NTT, invalid Q/P/gadget/level, limits, residues or trailing bytes.
    /// Source/target secret claims and honest key generation remain caller contracts.
    pub fn import_relinearization_key(
        &self,
        bytes: &[u8],
        limits: Limits,
    ) -> Result<BgvRelinearizationKey, Error> {
        let (key, _) = decode(self, bytes, limits, EvaluationKeyRole::Relinearization)?;
        Ok(BgvRelinearizationKey { key })
    }
    /// Encodes this typed public role key with its actual level, backend and Q/P.
    /// # Errors
    /// Rejects a key belonging to another local context. Export authenticates nothing.
    pub fn export_key_switching_key(&self, key: &BgvKeySwitchingKey) -> Result<Vec<u8>, Error> {
        encode(self, &key.key, EvaluationKeyRole::KeySwitching, 0)
    }
    /// Restores this typed role under the receiving context after complete validation.
    /// # Errors
    /// Rejects wrong role/context/NTT, invalid Q/P/gadget/level, limits, residues or trailing bytes.
    /// Source/target secret claims and honest key generation remain caller contracts.
    pub fn import_key_switching_key(
        &self,
        bytes: &[u8],
        limits: Limits,
    ) -> Result<BgvKeySwitchingKey, Error> {
        let (key, _) = decode(self, bytes, limits, EvaluationKeyRole::KeySwitching)?;
        Ok(BgvKeySwitchingKey { key })
    }
    /// Encodes this typed public role key with its actual level, backend and Q/P.
    /// # Errors
    /// Rejects a key belonging to another local context. Export authenticates nothing.
    pub fn export_automorphism_key(&self, key: &BgvAutomorphismKey) -> Result<Vec<u8>, Error> {
        encode(
            self,
            &key.key,
            EvaluationKeyRole::Automorphism,
            key.exponent,
        )
    }
    /// Restores this typed role under the receiving context after complete validation.
    /// # Errors
    /// Rejects wrong role/context/NTT, invalid Q/P/gadget/level, limits, residues or trailing bytes.
    /// Source/target secret claims and honest key generation remain caller contracts.
    pub fn import_automorphism_key(
        &self,
        bytes: &[u8],
        limits: Limits,
    ) -> Result<BgvAutomorphismKey, Error> {
        let (key, exponent) = decode(self, bytes, limits, EvaluationKeyRole::Automorphism)?;
        Ok(BgvAutomorphismKey {
            key,
            exponent,
            permutation: NttAutomorphismPermutation::new(exponent, self.parameters().poly_length()),
        })
    }
}
