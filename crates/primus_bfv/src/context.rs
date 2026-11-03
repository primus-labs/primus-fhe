use primus_encoding::{BfvRnsCodec, BfvRnsCodecError};
use primus_glwe_rns::RnsDomainError;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttError, U64DcrtTable};
use primus_rns::RNSBase;

use crate::{BfvCiphertext, BfvParameters, BfvPublicKey, BfvPublicKeyEncryptor};

/// Invalid transform parameters, prefix codec or requested number of levels.
#[derive(Debug, thiserror::Error)]
pub enum BfvContextError {
    /// The ciphertext basis does not support the required NTT.
    #[error(transparent)]
    Transform(#[from] NttError<u64>),
    /// A requested lower level fails the coefficient codec's recovery bounds.
    #[error(transparent)]
    Encoding(#[from] BfvRnsCodecError<u64>),
    /// There must be at least one level and at most one per ciphertext prime.
    #[error("BFV level count {requested} is outside 1..={maximum}")]
    LevelCount {
        /// Supplied number of levels, including the highest level.
        requested: usize,
        /// Number of primes in the highest ciphertext basis.
        maximum: usize,
    },
}

/// Shared immutable BFV resources for one ordered prefix chain.
///
/// Owns the supplied parameters, one NTT table for the full Q basis, and one
/// distinct codec for each requested lower Q. Sampling is prepared only once,
/// for fresh encryption at level zero. Clients and evaluators borrow this owner;
/// they do not clone codecs, tables or sampling state.
///
/// Level zero uses all primes; level `l` omits the last `l` primes. A ciphertext
/// is still a zero-copy storage container: operations check its complete length,
/// but callers must supply its actual level, this context's NTT convention and
/// the appropriate actual secret. Equal lengths alone do not prove identity.
pub struct BfvContext {
    parameters: BfvParameters,
    table: U64DcrtTable,
    lower_codecs: Vec<BfvRnsCodec<u64, BarrettModulus<u64>>>,
}

impl BfvContext {
    /// Prepares a single-level context without cloning its parameters.
    ///
    /// # Errors
    /// Rejects a basis that does not support the requested NTT.
    pub fn try_new(parameters: BfvParameters) -> Result<Self, BfvContextError> {
        Self::try_with_levels(parameters, 1)
    }

    /// Prepares the highest level and `level_count - 1` ordered prefix levels.
    ///
    /// Lower codecs share `t` and the auxiliary decoder modulus with the highest
    /// codec. They establish the codec's noiseless recovery bounds, not a fresh
    /// or evaluated ciphertext noise bound. Only requested levels are prepared.
    ///
    /// # Errors
    /// Rejects an invalid level count, unsupported NTT or lower codec parameters.
    pub fn try_with_levels(
        parameters: BfvParameters,
        level_count: usize,
    ) -> Result<Self, BfvContextError> {
        let maximum = parameters.base_q().moduli_count();
        if level_count == 0 || level_count > maximum {
            return Err(BfvContextError::LevelCount {
                requested: level_count,
                maximum,
            });
        }
        let mut lower_codecs = Vec::with_capacity(level_count - 1);
        for level in 1..level_count {
            let base = RNSBase::new(&parameters.base_q().moduli()[..maximum - level])
                .expect("a nonempty prefix of a valid RNS basis is valid");
            lower_codecs.push(BfvRnsCodec::try_new(
                BarrettModulus::new(parameters.codec().t()),
                base,
                BarrettModulus::new(parameters.codec().gamma()),
            )?);
        }
        let table = U64DcrtTable::new(parameters.poly_length(), parameters.base_q().moduli())?;
        Ok(Self {
            parameters,
            table,
            lower_codecs,
        })
    }

    /// Borrows the highest-level parameters, including the unique sampling state.
    #[must_use]
    pub fn parameters(&self) -> &BfvParameters {
        &self.parameters
    }

    /// Borrows the full-basis NTT table; lower levels use its ordered prefix.
    #[must_use]
    pub fn table(&self) -> &U64DcrtTable {
        &self.table
    }

    /// Returns the number of prepared levels, including level zero.
    #[must_use]
    pub fn level_count(&self) -> usize {
        self.lower_codecs.len() + 1
    }

    /// Borrows the unique coefficient codec for one prepared level.
    ///
    /// # Panics
    /// Panics if `level >= level_count()`.
    #[must_use]
    pub fn codec(&self, level: usize) -> &BfvRnsCodec<u64, BarrettModulus<u64>> {
        if level == 0 {
            self.parameters.codec()
        } else {
            self.lower_codecs.get(level - 1).expect("invalid BFV level")
        }
    }

    /// Returns the complete DCRT polynomial length at a prepared level.
    ///
    /// # Panics
    /// Panics if the requested level is not prepared.
    #[must_use]
    pub fn rns_poly_len(&self, level: usize) -> usize {
        self.codec(level).moduli_count() * self.parameters.poly_length().get()
    }

    /// Allocates a zeroed ciphertext with the complete shape of a prepared level.
    ///
    /// # Panics
    /// Panics if the requested level is not prepared.
    #[must_use]
    pub fn new_ciphertext(&self, level: usize) -> BfvCiphertext<Vec<u64>> {
        BfvCiphertext::zero(2 * self.rns_poly_len(level))
    }

    /// Prepares public encryption at level zero, reusing the owned resources.
    ///
    /// # Errors
    /// Rejects a public key with different geometry or ordered moduli. Matching
    /// numbers do not establish actual key identity or NTT convention.
    pub fn public_key_encryptor<'a>(
        &'a self,
        key: &'a BfvPublicKey,
    ) -> Result<BfvPublicKeyEncryptor<'a>, RnsDomainError<u64>> {
        BfvPublicKeyEncryptor::try_new(key, &self.parameters, &self.table)
    }
}
