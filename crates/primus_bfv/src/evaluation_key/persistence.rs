//! Public role-key storage. Actual secrets are never serialized.
use super::*;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_glwe_rns::persistence::{
    PublicObjectError as Error, PublicObjectLimits as Limits, decode_public_words, ntt_fingerprint,
};
use primus_glwe_rns::rlwe_parameters::validate_ntt_primes;

fn encode(
    context: &BfvContext,
    key: &NativeEvaluationKey,
    role: u64,
    exponent: usize,
) -> Result<Vec<u8>, Error> {
    key.validate(context).map_err(Error::parameters)?;
    let mut writer = context.public_writer(role);
    writer.usize(key.level);
    writer.usize(exponent);
    match &key.basis {
        NativeEvaluationBasis::Radix(metadata) => {
            writer.u64(0);
            writer.u64(u64::from(metadata.basis().log_basis().get()));
            writer.usize(metadata.basis().level_count().get());
        }
        NativeEvaluationBasis::Hybrid(metadata) => {
            writer.u64(1);
            writer.usize(metadata.hybrid_rns().partitioning().full_q_moduli_count());
            writer.usize(metadata.hybrid_rns().decomposition_count());
            writer.words(metadata.hybrid_rns().p_base().moduli_values());
            writer.digest(&ntt_fingerprint(metadata.table_p()));
        }
    }
    writer.words(&key.columns);
    Ok(writer.finish())
}

// Parse geometry and scan the full payload before allocating native role owners.
// The temporary configuration contains only bounded small public metadata.
fn decode(
    context: &BfvContext,
    bytes: &[u8],
    limits: Limits,
    role: u64,
) -> Result<(NativeEvaluationKey, usize), Error> {
    enum Configuration {
        Radix(DecompositionConfig, usize),
        Hybrid {
            full: usize,
            digits: usize,
            p: Vec<u64>,
            digest: [u8; 32],
        },
    }
    let mut reader = context.public_reader(bytes, role, limits)?;
    let level = reader.usize(context.level_count() - 1)?;
    let n = context.parameters().poly_length().get();
    let exponent = reader.usize(2 * n - 1)?;
    if (role == 5 && exponent.is_multiple_of(2)) || (role != 5 && exponent != 0) {
        return Err(Error::Malformed("role exponent"));
    }
    let base = context.codec(level).base_q();
    let mut moduli = base.moduli_values().to_vec();
    let (configuration, columns) = match reader.u64()? {
        0 => {
            let log = u32::try_from(reader.u64()?).map_err(|_| Error::Malformed("radix log"))?;
            if !(2..64).contains(&log) {
                return Err(Error::Malformed("radix log"));
            }
            let bits = base.moduli_product().bit_width() as usize;
            let count = reader.usize(bits / (log as usize))?;
            let config = DecompositionConfig {
                log_basis: DecompositionBaseLog::try_new(log).map_err(Error::parameters)?,
                level_count: Some(
                    DecompositionLevelCount::try_new(count).map_err(Error::parameters)?,
                ),
            };
            (Configuration::Radix(config, count), count)
        }
        1 => {
            let full = reader.usize(limits.max_moduli)?;
            let digits = reader.usize(full)?;
            let p = reader.words(limits.max_moduli)?;
            if full < base.moduli_count() || digits == 0 || p.is_empty() {
                return Err(Error::Malformed("Hybrid geometry"));
            }
            let width = full.div_ceil(digits);
            if full.div_ceil(width) != digits {
                return Err(Error::Malformed("Hybrid partitioning"));
            }
            moduli.extend_from_slice(&p);
            limits.context(n, moduli.len(), 1)?;
            validate_ntt_primes(n, &moduli).map_err(Error::parameters)?;
            let digest = reader.digest()?;
            let columns = base.moduli_count().div_ceil(width);
            (
                Configuration::Hybrid {
                    full,
                    digits,
                    p,
                    digest,
                },
                columns,
            )
        }
        _ => return Err(Error::Malformed("key backend")),
    };
    let count = n
        .checked_mul(moduli.len())
        .and_then(|x| x.checked_mul(columns))
        .and_then(|x| x.checked_mul(2))
        .ok_or(Error::Limit("key geometry overflow"))?;
    let data = reader.canonical_bytes(count, n, &moduli)?;
    reader.finish()?;
    let config = match configuration {
        Configuration::Radix(config, expected) => {
            let metadata = context
                .radix_key_parameters(level, config)
                .map_err(Error::parameters)?;
            if metadata.basis().level_count().get() != expected {
                return Err(Error::Malformed("radix columns"));
            }
            EvaluationKeyConfig::PreparedRadix(metadata)
        }
        Configuration::Hybrid {
            full,
            digits,
            p,
            digest,
        } => {
            let metadata = Arc::new(
                NativeHybridParameters::try_new(
                    context.parameters().poly_length(),
                    base,
                    full,
                    &p,
                    digits,
                )
                .map_err(Error::parameters)?,
            );
            if ntt_fingerprint(metadata.table_p()) != digest {
                return Err(Error::Binding);
            }
            EvaluationKeyConfig::Hybrid(metadata)
        }
    };
    let mut key =
        NativeEvaluationKey::prepare_metadata(context, level, config).map_err(Error::parameters)?;
    if key.key_len() != count {
        return Err(Error::Malformed("key columns"));
    }
    key.columns = decode_public_words(data);
    Ok((key, exponent))
}

impl BfvContext {
    /// Encodes this typed public role key with its actual level, backend and Q/P.
    /// # Errors
    /// Rejects a key belonging to another local context. Export authenticates nothing.
    pub fn export_relinearization_key(
        &self,
        key: &BfvRelinearizationKey,
    ) -> Result<Vec<u8>, Error> {
        encode(self, &key.key, 3, 0)
    }
    /// Restores this typed role under the receiving context after complete validation.
    /// # Errors
    /// Rejects wrong role/context/NTT, invalid Q/P/gadget/level, limits, residues or trailing bytes.
    /// Source/target secret claims and honest key generation remain caller contracts.
    pub fn import_relinearization_key(
        &self,
        bytes: &[u8],
        limits: Limits,
    ) -> Result<BfvRelinearizationKey, Error> {
        let (key, _) = decode(self, bytes, limits, 3)?;
        Ok(BfvRelinearizationKey { key })
    }
    /// Encodes this typed public role key with its actual level, backend and Q/P.
    /// # Errors
    /// Rejects a key belonging to another local context. Export authenticates nothing.
    pub fn export_key_switching_key(&self, key: &BfvKeySwitchingKey) -> Result<Vec<u8>, Error> {
        encode(self, &key.key, 4, 0)
    }
    /// Restores this typed role under the receiving context after complete validation.
    /// # Errors
    /// Rejects wrong role/context/NTT, invalid Q/P/gadget/level, limits, residues or trailing bytes.
    /// Source/target secret claims and honest key generation remain caller contracts.
    pub fn import_key_switching_key(
        &self,
        bytes: &[u8],
        limits: Limits,
    ) -> Result<BfvKeySwitchingKey, Error> {
        let (key, _) = decode(self, bytes, limits, 4)?;
        Ok(BfvKeySwitchingKey { key })
    }
    /// Encodes this typed public role key with its actual level, backend and Q/P.
    /// # Errors
    /// Rejects a key belonging to another local context. Export authenticates nothing.
    pub fn export_automorphism_key(&self, key: &BfvAutomorphismKey) -> Result<Vec<u8>, Error> {
        encode(self, &key.key, 5, key.exponent)
    }
    /// Restores this typed role under the receiving context after complete validation.
    /// # Errors
    /// Rejects wrong role/context/NTT, invalid Q/P/gadget/level, limits, residues or trailing bytes.
    /// Source/target secret claims and honest key generation remain caller contracts.
    pub fn import_automorphism_key(
        &self,
        bytes: &[u8],
        limits: Limits,
    ) -> Result<BfvAutomorphismKey, Error> {
        let (key, exponent) = decode(self, bytes, limits, 5)?;
        Ok(BfvAutomorphismKey {
            key,
            exponent,
            permutation: NttAutomorphismPermutation::new(exponent, self.parameters().poly_length()),
        })
    }
}
