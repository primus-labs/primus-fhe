//! Bounded binary primitives for public BFV/BGV storage.
//!
//! These containers are separate from protocol-round payloads. They never store
//! secrets or process-local identities. Structural checks do not authenticate a
//! sender, prove an actual secret relation, or establish a security/noise bound.

use primus_distr::{BlockOccupancy, ErrorDistribution, SecretKeyDistr};
use primus_ntt::{MonomialNttTable, U64DcrtTable};
use sha2::{Digest, Sha256};

/// Application-selected bounds, checked before preparing imported resources.
#[derive(Clone, Copy, Debug)]
pub struct PublicObjectLimits {
    /// Maximum complete encoded object size in bytes.
    pub max_bytes: usize,
    /// Maximum full-ring coefficient count.
    pub max_poly_length: usize,
    /// Maximum number of moduli in a single ordered basis.
    pub max_moduli: usize,
    /// Maximum payload words and conservative preparation work in word units.
    pub max_words: usize,
    /// Maximum accepted Gaussian scale before preparing any sampling table.
    pub max_gaussian_standard_deviation: f64,
}

impl Default for PublicObjectLimits {
    fn default() -> Self {
        Self {
            max_bytes: 256 << 20,
            max_poly_length: 1 << 17,
            max_moduli: 64,
            max_words: 64 << 20,
            max_gaussian_standard_deviation: 64.0,
        }
    }
}

impl PublicObjectLimits {
    /// Checks a payload or preparation count without allocating.
    pub fn words(self, words: usize) -> Result<(), PublicObjectError> {
        if words > self.max_words {
            return Err(PublicObjectError::Limit("word budget"));
        }
        Ok(())
    }

    /// Checks NTT/CRT preparation without constructing numerical owners.
    /// The deliberately conservative charge is `16*N*Q*levels + 256*Q^3`;
    /// it is an admission budget, not a measurement of allocator RSS.
    pub fn context(self, n: usize, q: usize, levels: usize) -> Result<(), PublicObjectError> {
        self.words(self.context_words(n, q, levels)?)
    }

    /// Checks complete context preparation including its actual Gaussian samplers.
    /// Each Gaussian adds 16,384 words for the bounded 512-layer Ziggurat arrays,
    /// construction scratch and CDT alternative; CBD needs no persistent table.
    pub fn context_with_sampling(
        self,
        n: usize,
        q: usize,
        levels: usize,
        secret: SecretKeyDistr,
        error: ErrorDistribution,
    ) -> Result<(), PublicObjectError> {
        let samplers = usize::from(matches!(secret, SecretKeyDistr::Gaussian { .. }))
            + usize::from(matches!(error, ErrorDistribution::Gaussian { .. }));
        let words = self
            .context_words(n, q, levels)?
            .checked_add(samplers * 16_384)
            .ok_or(PublicObjectError::Limit("sampler preparation overflow"))?;
        self.words(words)
    }

    fn context_words(self, n: usize, q: usize, levels: usize) -> Result<usize, PublicObjectError> {
        if n > self.max_poly_length || q == 0 || q > self.max_moduli || levels == 0 || levels > q {
            return Err(PublicObjectError::Limit("context geometry"));
        }
        let count = n
            .checked_mul(q)
            .and_then(|x| x.checked_mul(levels))
            .and_then(|x| x.checked_mul(16))
            .and_then(|x| {
                q.checked_mul(q)?
                    .checked_mul(q)?
                    .checked_mul(256)?
                    .checked_add(x)
            })
            .ok_or(PublicObjectError::Limit("context preparation overflow"))?;
        Ok(count)
    }
}

/// A rejected public storage container.
#[derive(Debug, thiserror::Error)]
pub enum PublicObjectError {
    /// An application-selected size or preparation limit was exceeded.
    #[error("public object resource limit: {0}")]
    Limit(&'static str),
    /// Header, role, length, value or trailing bytes are malformed.
    #[error("malformed public object: {0}")]
    Malformed(&'static str),
    /// The complete numerical context or actual NTT representation differs.
    #[error("public object context or NTT representation mismatch")]
    Binding,
    /// A checked numerical owner rejected the imported parameters.
    #[error("invalid public object parameters: {0}")]
    Parameters(String),
}

impl PublicObjectError {
    /// Preserves a checked constructor's diagnostic without exposing its type.
    pub fn parameters(error: impl std::fmt::Display) -> Self {
        Self::Parameters(error.to_string())
    }
}

/// Little-endian frame writer used by the two scheme owners.
pub struct PublicObjectWriter(Vec<u8>);
impl PublicObjectWriter {
    /// Starts representation version1, native plus-phase modulus-major u64 NTT.
    #[must_use]
    pub fn new(scheme: u64, role: u64) -> Self {
        let mut writer = Self(b"PRFHEPUB".to_vec());
        writer.u64(1);
        writer.u64(scheme);
        writer.u64(role);
        writer
    }
    /// Writes a scalar.
    pub fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    /// Writes a machine count as a portable u64.
    pub fn usize(&mut self, value: usize) {
        self.u64(value as u64);
    }
    /// Writes a length-prefixed byte string.
    pub fn blob(&mut self, value: &[u8]) {
        self.usize(value.len());
        self.0.extend_from_slice(value);
    }
    /// Writes a length-prefixed word vector.
    pub fn words(&mut self, value: &[u64]) {
        self.usize(value.len());
        for &word in value {
            self.u64(word);
        }
    }
    /// Writes a fixed SHA-256 representation digest.
    pub fn digest(&mut self, value: &[u8; 32]) {
        self.0.extend_from_slice(value);
    }
    /// Returns the complete encoded frame.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Borrowing parser; payload geometry and canonicality are checked before copies.
pub struct PublicObjectReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
    limits: PublicObjectLimits,
}
impl<'a> PublicObjectReader<'a> {
    /// Checks the complete byte cap, format version, scheme and expected role.
    pub fn new(
        bytes: &'a [u8],
        scheme: u64,
        role: u64,
        limits: PublicObjectLimits,
    ) -> Result<Self, PublicObjectError> {
        if bytes.len() > limits.max_bytes {
            return Err(PublicObjectError::Limit("encoded bytes"));
        }
        let mut reader = Self {
            bytes,
            cursor: 0,
            limits,
        };
        if reader.take(8)? != b"PRFHEPUB"
            || reader.u64()? != 1
            || reader.u64()? != scheme
            || reader.u64()? != role
        {
            return Err(PublicObjectError::Malformed("format, scheme or role"));
        }
        Ok(reader)
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], PublicObjectError> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or(PublicObjectError::Malformed("length overflow"))?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(PublicObjectError::Malformed("truncated input"))?;
        self.cursor = end;
        Ok(value)
    }
    /// Reads one scalar.
    pub fn u64(&mut self) -> Result<u64, PublicObjectError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("checked eight bytes"),
        ))
    }
    /// Reads a portable count and checks an application bound before use.
    pub fn usize(&mut self, maximum: usize) -> Result<usize, PublicObjectError> {
        let value =
            usize::try_from(self.u64()?).map_err(|_| PublicObjectError::Limit("count overflow"))?;
        if value > maximum {
            return Err(PublicObjectError::Limit("count"));
        }
        Ok(value)
    }
    /// Borrows a complete bounded byte string without allocating.
    pub fn blob(&mut self) -> Result<&'a [u8], PublicObjectError> {
        let n = self.usize(self.limits.max_bytes)?;
        self.take(n)
    }
    /// Reads a bounded short vector, as used by ordered public Q/P metadata.
    pub fn words(&mut self, maximum: usize) -> Result<Vec<u64>, PublicObjectError> {
        let n = self.usize(maximum.min(self.limits.max_words))?;
        let bytes = self.take(
            n.checked_mul(8)
                .ok_or(PublicObjectError::Limit("word bytes"))?,
        )?;
        Ok(decode_public_words(bytes))
    }
    /// Borrows validated complete native NTT payload words before allocation.
    pub fn canonical_bytes(
        &mut self,
        count: usize,
        n: usize,
        moduli: &[u64],
    ) -> Result<&'a [u8], PublicObjectError> {
        self.limits.words(count)?;
        let polynomial = n
            .checked_mul(moduli.len())
            .filter(|&length| length != 0)
            .ok_or(PublicObjectError::Malformed("payload geometry"))?;
        if self.usize(count)? != count || !count.is_multiple_of(polynomial) {
            return Err(PublicObjectError::Malformed("payload geometry"));
        }
        let bytes = self.take(
            count
                .checked_mul(8)
                .ok_or(PublicObjectError::Limit("payload bytes"))?,
        )?;
        for (index, word) in bytes.as_chunks::<8>().0.iter().enumerate() {
            if u64::from_le_bytes(*word) >= moduli[(index / n) % moduli.len()] {
                return Err(PublicObjectError::Malformed("noncanonical residue"));
            }
        }
        Ok(bytes)
    }
    /// Reads one fixed digest.
    pub fn digest(&mut self) -> Result<[u8; 32], PublicObjectError> {
        Ok(self.take(32)?.try_into().expect("checked digest"))
    }
    /// Rejects all unconsumed trailing bytes.
    pub fn finish(self) -> Result<(), PublicObjectError> {
        if self.cursor != self.bytes.len() {
            return Err(PublicObjectError::Malformed("trailing bytes"));
        }
        Ok(())
    }
}

/// Copies already length/canonicality-checked LE words into owned native storage.
/// # Panics
/// Rejects an incomplete final word before allocating; canonicality belongs to
/// the scheme's complete payload validation.
#[must_use]
pub fn decode_public_words(bytes: &[u8]) -> Vec<u64> {
    assert!(
        bytes.len().is_multiple_of(8),
        "public words need complete eight-byte words"
    );
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|&word| u64::from_le_bytes(word))
        .collect()
}

/// Hashes all actual forward/inverse roots and their order, independently of CPU backend.
#[must_use]
pub fn ntt_fingerprint(table: &U64DcrtTable) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"primus-native-u64-plus-ntt-v1");
    for limb in table.ntt_tables() {
        for roots in [limb.root_powers(), limb.inv_root_powers()] {
            hash.update((roots.len() as u64).to_le_bytes());
            for &root in roots {
                hash.update(root.to_le_bytes());
            }
        }
    }
    hash.finalize().into()
}

/// Stores the complete public secret/error sampler descriptions, not samples.
pub fn write_sampling(
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

/// Reads bounded sampler descriptions before any Gaussian preparation.
pub fn read_sampling(
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
