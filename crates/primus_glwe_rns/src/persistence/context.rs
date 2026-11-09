//! Shared description tail for native BFV and BGV contexts.
use primus_distr::{BlockOccupancy, ErrorDistribution, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;

use crate::rlwe_parameters::validate_ntt_primes;

use super::{PublicObjectError, PublicObjectLimits, PublicObjectReader, PublicObjectWriter};

/// Ordered Q, prepared levels, sampler laws and actual NTT digest.
///
/// Each scheme supplies its own plaintext encoding fields before this shared
/// description. The decoded description carries checked moduli without yet
/// allocating a numerical context or a sampler.
pub struct PublicContextDescription<Q> {
    /// Number of prepared prefix levels, including the highest level.
    pub levels: usize,
    /// Ordered highest-level ciphertext moduli.
    pub moduli: Q,
    /// Secret-key sampling law.
    pub secret: SecretKeyDistr,
    /// Error sampling law.
    pub error: ErrorDistribution,
    /// Digest of the actual forward and inverse NTT roots.
    pub ntt_digest: [u8; 32],
}

impl PublicContextDescription<&[u64]> {
    /// Writes the shared part of the context description.
    pub fn write(self, writer: &mut PublicObjectWriter) {
        writer.usize(self.levels);
        writer.words(self.moduli);
        write_sampling(writer, self.secret, self.error);
        writer.digest(&self.ntt_digest);
    }
}

impl PublicContextDescription<Vec<BarrettModulus<u64>>> {
    /// Reads the complete remaining description after the scheme-specific fields.
    ///
    /// # Errors
    /// Rejects invalid geometry, Q primes, sampling descriptions, resource limits
    /// and trailing bytes before the caller allocates context resources.
    pub fn read(
        mut reader: PublicObjectReader<'_>,
        length: PolyLength,
    ) -> Result<Self, PublicObjectError> {
        let limits = reader.limits;
        let levels = reader.usize(limits.max_moduli)?;
        let primes = reader.words(limits.max_moduli)?;
        let (secret, error) = read_sampling(&mut reader, length.get(), limits)?;
        let ntt_digest = reader.digest()?;
        reader.finish()?;
        limits.context_with_sampling(length.get(), primes.len(), levels, secret, error)?;
        validate_ntt_primes(length.get(), &primes).map_err(PublicObjectError::parameters)?;
        let moduli = primes
            .into_iter()
            .map(|q| BarrettModulus::try_new(q).ok_or(PublicObjectError::Malformed("Q modulus")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            levels,
            moduli,
            secret,
            error,
            ntt_digest,
        })
    }
}

fn write_sampling(
    writer: &mut PublicObjectWriter,
    secret: SecretKeyDistr,
    error: ErrorDistribution,
) {
    use SecretKeyDistr::*;
    match secret {
        UniformBinary => writer.u64(0),
        Binary { one_probability } => {
            writer.u64(1);
            writer.u64(one_probability.to_bits());
        }
        SparseTernary => writer.u64(2),
        UniformTernary => writer.u64(3),
        Ternary {
            negative_one_probability,
            one_probability,
        } => {
            writer.u64(4);
            writer.u64(negative_one_probability.to_bits());
            writer.u64(one_probability.to_bits());
        }
        FixedHammingWeightBinary { hamming_weight } => {
            writer.u64(5);
            writer.usize(hamming_weight);
        }
        BlockBinary {
            block_size,
            occupancy,
        } => {
            writer.u64(6);
            writer.usize(block_size);
            writer.u64(u64::from(occupancy == BlockOccupancy::ExactlyOne));
        }
        FixedHammingWeightTernary { hamming_weight } => {
            writer.u64(7);
            writer.usize(hamming_weight);
        }
        FixedCompositionTernary {
            negative_one_weight,
            one_weight,
        } => {
            writer.u64(8);
            writer.usize(negative_one_weight);
            writer.usize(one_weight);
        }
        Gaussian { standard_deviation } => {
            writer.u64(9);
            writer.u64(standard_deviation.to_bits());
        }
    }
    match error {
        ErrorDistribution::Gaussian { standard_deviation } => {
            writer.u64(0);
            writer.u64(standard_deviation.to_bits());
        }
        ErrorDistribution::CenteredBinomial { eta } => {
            writer.u64(1);
            writer.u64(u64::from(eta));
        }
    }
}

fn read_sampling(
    reader: &mut PublicObjectReader<'_>,
    n: usize,
    limits: PublicObjectLimits,
) -> Result<(SecretKeyDistr, ErrorDistribution), PublicObjectError> {
    fn gaussian(
        reader: &mut PublicObjectReader<'_>,
        limits: PublicObjectLimits,
    ) -> Result<f64, PublicObjectError> {
        let x = f64::from_bits(reader.u64()?);
        if !x.is_finite()
            || x <= 0.0
            || !limits.max_gaussian_standard_deviation.is_finite()
            || x > limits.max_gaussian_standard_deviation
        {
            return Err(PublicObjectError::Limit("Gaussian scale"));
        }
        Ok(x)
    }
    fn probability(reader: &mut PublicObjectReader<'_>) -> Result<f64, PublicObjectError> {
        let x = f64::from_bits(reader.u64()?);
        if !x.is_finite() || !(0.0..=1.0).contains(&x) {
            return Err(PublicObjectError::Malformed("secret probability"));
        }
        Ok(x)
    }
    use SecretKeyDistr::*;
    let secret = match reader.u64()? {
        0 => UniformBinary,
        1 => Binary {
            one_probability: probability(reader)?,
        },
        2 => SparseTernary,
        3 => UniformTernary,
        4 => {
            let negative_one_probability = probability(reader)?;
            let one_probability = probability(reader)?;
            if negative_one_probability > 1.0 - one_probability {
                return Err(PublicObjectError::Malformed("secret probabilities"));
            }
            Ternary {
                negative_one_probability,
                one_probability,
            }
        }
        5 => FixedHammingWeightBinary {
            hamming_weight: reader.usize(n)?,
        },
        6 => {
            let block_size = reader.usize(n)?;
            let occupancy = match reader.u64()? {
                0 => BlockOccupancy::AtMostOne,
                1 => BlockOccupancy::ExactlyOne,
                _ => return Err(PublicObjectError::Malformed("block occupancy")),
            };
            if block_size == 0 || !n.is_multiple_of(block_size) {
                return Err(PublicObjectError::Malformed("block size"));
            }
            BlockBinary {
                block_size,
                occupancy,
            }
        }
        7 => FixedHammingWeightTernary {
            hamming_weight: reader.usize(n)?,
        },
        8 => {
            let negative_one_weight = reader.usize(n)?;
            let one_weight = reader.usize(n)?;
            if negative_one_weight > n - one_weight {
                return Err(PublicObjectError::Malformed("composition weights"));
            }
            FixedCompositionTernary {
                negative_one_weight,
                one_weight,
            }
        }
        9 => Gaussian {
            standard_deviation: gaussian(reader, limits)?,
        },
        _ => return Err(PublicObjectError::Malformed("secret distribution")),
    };
    let error = match reader.u64()? {
        0 => ErrorDistribution::Gaussian {
            standard_deviation: gaussian(reader, limits)?,
        },
        1 => {
            let eta = reader.usize(32)?;
            if eta == 0 {
                return Err(PublicObjectError::Malformed("CBD eta"));
            }
            ErrorDistribution::CenteredBinomial { eta: eta as u32 }
        }
        _ => return Err(PublicObjectError::Malformed("error distribution")),
    };
    Ok((secret, error))
}
