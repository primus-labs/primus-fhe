//! Shared native role-key descriptions and bounded column decoding.
use std::{borrow::Cow, sync::Arc};

use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_lattice::{
    hybrid::{EvaluationKeyConfig, NativeHybridParameters},
    radix::NativeRadixParameters,
};
use primus_modulus::BarrettModulus;
use primus_rns::RNSBase;
use primus_shape::PolyLength;

use crate::rlwe_parameters::validate_ntt_primes;

use super::{PublicObjectError as Error, PublicObjectReader, PublicObjectWriter, ntt_fingerprint};

/// Typed role tags used by both schemes' public evaluation-key storage.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum EvaluationKeyRole {
    /// Quadratic to linear conversion.
    Relinearization = 3,
    /// A change of the ciphertext secret.
    KeySwitching = 4,
    /// One ring automorphism.
    Automorphism = 5,
}

impl PublicObjectWriter {
    /// Writes the native radix backend tag and actual digit description.
    pub fn write_radix_key(&mut self, parameters: &NativeRadixParameters) {
        self.u64(0);
        self.u64(u64::from(parameters.basis().log_basis().get()));
        self.usize(parameters.basis().level_count().get());
    }

    /// Writes the native Hybrid backend tag, partitioning and auxiliary P descriptor.
    pub fn write_hybrid_key(&mut self, parameters: &NativeHybridParameters) {
        self.u64(1);
        self.usize(parameters.hybrid_rns().partitioning().full_q_moduli_count());
        self.usize(parameters.hybrid_rns().decomposition_count());
        self.words(parameters.hybrid_rns().p_base().moduli_values());
        self.digest(&ntt_fingerprint(parameters.table_p()));
    }
}

/// A checked native backend description and borrowed canonical columns.
///
/// Scheme owners apply their own level, sampling and phase checks before
/// adopting the columns.
pub struct DecodedEvaluationKey<'a> {
    /// Actual automorphism exponent, or zero for the two other roles.
    pub exponent: usize,
    /// Decoded backend configuration with prepared Hybrid resources.
    pub config: EvaluationKeyConfig,
    /// Complete modulus-major little-endian key column words.
    pub columns: &'a [u8],
}

impl<'a> DecodedEvaluationKey<'a> {
    /// Reads a role descriptor and its complete canonical columns after level selection.
    ///
    /// # Errors
    /// Rejects invalid exponent, backend, gadget geometry, actual P transform,
    /// resource budgets, residues or trailing bytes. The full frame is checked
    /// before allocating Hybrid arithmetic resources or copying columns.
    pub fn read(
        mut reader: PublicObjectReader<'a>,
        role: EvaluationKeyRole,
        length: PolyLength,
        base: &RNSBase<u64, BarrettModulus<u64>>,
    ) -> Result<Self, Error> {
        enum Description {
            Radix(DecompositionConfig),
            Hybrid {
                full: usize,
                digits: usize,
                p: Vec<u64>,
                digest: [u8; 32],
            },
        }

        let n = length.get();
        let max_exponent = n
            .checked_mul(2)
            .and_then(|order| order.checked_sub(1))
            .ok_or(Error::Limit("automorphism order overflow"))?;
        let exponent = reader.usize(max_exponent)?;
        match role {
            EvaluationKeyRole::Automorphism if !exponent.is_multiple_of(2) => {}
            EvaluationKeyRole::Relinearization | EvaluationKeyRole::KeySwitching
                if exponent == 0 => {}
            _ => return Err(Error::Malformed("role exponent")),
        }
        let limits = reader.limits;
        let mut moduli = Cow::Borrowed(base.moduli_values());
        let (description, digit_count) = match reader.u64()? {
            0 => {
                let log =
                    u32::try_from(reader.u64()?).map_err(|_| Error::Malformed("radix log"))?;
                if !(2..64).contains(&log) {
                    return Err(Error::Malformed("radix log"));
                }
                let bits = base.moduli_product().bit_width() as usize;
                let count = reader.usize(bits / log as usize)?;
                let config = DecompositionConfig {
                    log_basis: DecompositionBaseLog::try_new(log).map_err(Error::parameters)?,
                    level_count: Some(
                        DecompositionLevelCount::try_new(count).map_err(Error::parameters)?,
                    ),
                };
                (Description::Radix(config), count)
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
                moduli.to_mut().extend_from_slice(&p);
                limits.context(n, moduli.len(), 1)?;
                validate_ntt_primes(n, &moduli).map_err(Error::parameters)?;
                let digest = reader.digest()?;
                (
                    Description::Hybrid {
                        full,
                        digits,
                        p,
                        digest,
                    },
                    base.moduli_count().div_ceil(width),
                )
            }
            _ => return Err(Error::Malformed("key backend")),
        };
        let count = n
            .checked_mul(moduli.len())
            .and_then(|x| x.checked_mul(digit_count))
            .and_then(|x| x.checked_mul(2))
            .ok_or(Error::Limit("key geometry overflow"))?;
        let columns = reader.canonical_bytes(count, n, &moduli)?;
        reader.finish()?;
        let config = match description {
            Description::Radix(config) => EvaluationKeyConfig::Radix(config),
            Description::Hybrid {
                full,
                digits,
                p,
                digest,
            } => {
                let metadata = NativeHybridParameters::try_new(length, base, full, &p, digits)
                    .map_err(Error::parameters)?;
                if ntt_fingerprint(metadata.table_p()) != digest {
                    return Err(Error::Binding);
                }
                EvaluationKeyConfig::Hybrid(Arc::new(metadata))
            }
        };
        Ok(Self {
            exponent,
            config,
            columns,
        })
    }
}
