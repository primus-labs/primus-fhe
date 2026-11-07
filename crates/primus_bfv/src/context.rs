use primus_encoding::{BfvRnsCodec, BfvRnsCodecError};
use primus_glwe_rns::RnsDomainError;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttError, U64DcrtTable};
use primus_poly::Polynomial;
use std::sync::Arc;

use crate::keys::{BfvPublicKey, BfvPublicKeyEncryptor, BfvPublicKeyError};
use crate::quadratic::BfvQuadraticCiphertext;
use crate::{BfvCiphertext, BfvParameters};

/// Invalid transform parameters, prefix codec or requested number of levels.
#[derive(Debug, thiserror::Error)]
pub enum BfvContextError {
    /// The ciphertext basis does not support the required NTT.
    #[error(transparent)]
    Transform(#[from] NttError<u64>),
    /// The supplied shared table differs from the parameter geometry or ordered Q.
    #[error(transparent)]
    Binding(#[from] RnsDomainError<u64>),
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
/// Owns the supplied parameters, a shared NTT table for the full Q basis, and one
/// distinct codec for each requested lower Q. Sampling is prepared only once,
/// for fresh encryption at level zero. Clients and evaluators borrow this owner;
/// they do not clone codecs, tables or sampling state.
///
/// Level zero uses all primes; level `l` omits the last `l` primes. A ciphertext
/// allocated by this owner retains its local context provenance and level.
/// Operations reject foreign bound storage even when its shape is identical.
/// Explicit raw storage retains caller-owned representation/secret contracts;
/// local provenance does not prove the actual coefficient secret or noise bound.
pub struct BfvContext {
    identity: Arc<()>,
    pub(crate) public_descriptor: std::sync::OnceLock<Vec<u8>>,
    parameters: BfvParameters,
    table: Arc<U64DcrtTable>,
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
    /// Lower codecs share the highest codec's `t`/`gamma` basis precomputation.
    /// They establish the codec's noiseless recovery bounds, not a fresh
    /// or evaluated ciphertext noise bound. Only requested levels are prepared.
    ///
    /// # Errors
    /// Rejects an invalid level count, unsupported NTT or lower codec parameters.
    pub fn try_with_levels(
        parameters: BfvParameters,
        level_count: usize,
    ) -> Result<Self, BfvContextError> {
        Self::validate_level_count(&parameters, level_count)?;
        let table = Arc::new(U64DcrtTable::new(
            parameters.poly_length(),
            parameters.base_q().moduli(),
        )?);
        Self::from_bound_table(parameters, level_count, table)
    }

    /// Consumes parameters and shares an existing immutable full-Q transform table.
    ///
    /// This is useful for paired scheme contexts using the same actual transform.
    /// Lower codecs retain their scheme-specific scaling and recovery constants.
    ///
    /// # Errors
    /// Rejects an invalid level count, a table with different N/ordered Q, or an
    /// invalid lower codec. Numerical agreement does not establish secret identity.
    pub fn try_with_table(
        parameters: BfvParameters,
        level_count: usize,
        table: Arc<U64DcrtTable>,
    ) -> Result<Self, BfvContextError> {
        Self::validate_level_count(&parameters, level_count)?;
        parameters.encryption_parameters().validate_table(&table)?;
        Self::from_bound_table(parameters, level_count, table)
    }

    fn validate_level_count(
        parameters: &BfvParameters,
        requested: usize,
    ) -> Result<(), BfvContextError> {
        let maximum = parameters.base_q().moduli_count();
        if requested == 0 || requested > maximum {
            return Err(BfvContextError::LevelCount { requested, maximum });
        }
        Ok(())
    }

    // Both callers established N/Q/table and level geometry; only genuinely new
    // prefix codecs remain to be prepared here.
    fn from_bound_table(
        parameters: BfvParameters,
        level_count: usize,
        table: Arc<U64DcrtTable>,
    ) -> Result<Self, BfvContextError> {
        let maximum = parameters.base_q().moduli_count();
        let mut lower_codecs = Vec::with_capacity(level_count - 1);
        for level in 1..level_count {
            lower_codecs.push(parameters.codec().try_prefix(maximum - level)?);
        }
        Ok(Self {
            identity: Arc::new(()),
            public_descriptor: std::sync::OnceLock::new(),
            parameters,
            table,
            lower_codecs,
        })
    }

    pub(crate) fn identity(&self) -> &Arc<()> {
        &self.identity
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

    /// Shares this context's actual immutable table without copying its roots.
    #[must_use]
    pub fn shared_table(&self) -> Arc<U64DcrtTable> {
        Arc::clone(&self.table)
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

    /// Allocates N zero coefficients using this context's full plaintext ring.
    #[must_use]
    pub fn new_plaintext(&self) -> Polynomial<Vec<u64>> {
        Polynomial::zero(self.parameters.poly_length().get())
    }

    /// Prepares a full-ring slot encoder from this context's N and plaintext modulus.
    ///
    /// The returned encoder owns the single plaintext NTT table; this context
    /// does not cache another copy. Prepare it once and reuse it. For a smaller
    /// plaintext subring, construct [`primus_encoding::BatchingEncoder`] explicitly.
    ///
    /// # Correctness
    /// The plaintext modulus must be prime, as required by the encoder.
    /// # Errors
    /// Rejects a plaintext modulus that cannot support full-ring batching.
    #[cfg(feature = "batching")]
    pub fn batching_encoder(&self) -> Result<primus_encoding::BatchingEncoder, NttError<u64>> {
        primus_encoding::BatchingEncoder::try_new(
            self.parameters.poly_length(),
            BarrettModulus::new(self.parameters.codec().t()),
        )
    }

    /// Allocates zeroed output with this immutable context/level provenance.
    ///
    /// # Panics
    /// Panics if the requested level is not prepared.
    #[must_use]
    pub fn new_ciphertext(&self, level: usize) -> BfvCiphertext<Vec<u64>> {
        BfvCiphertext::bound(vec![0; 2 * self.rns_poly_len(level)], self, level)
    }

    /// Checks local provenance, level and complete shape without scanning words.
    ///
    /// A bound ciphertext must have this owner and exact level. For explicit raw
    /// storage this checks only geometry; ordered Q, actual NTT, scale and secret
    /// remain caller contracts. This does not certify canonical residues.
    /// # Errors
    /// Rejects an unavailable level, foreign provenance or incomplete storage.
    pub fn check_ciphertext<C: primus_data::Data<Elem = u64>>(
        &self,
        ciphertext: &BfvCiphertext<C>,
        level: usize,
    ) -> Result<(), crate::BfvCiphertextBindingError> {
        use crate::BfvCiphertextBindingError as E;
        if level >= self.level_count() {
            return Err(E::Level {
                requested: level,
                available: self.level_count(),
            });
        }
        ciphertext.validate_binding(self, level)?;
        let expected = 2 * self.rns_poly_len(level);
        let actual = ciphertext.as_ref().len();
        if actual != expected {
            return Err(E::Length { expected, actual });
        }
        Ok(())
    }

    /// Adopts a complete canonical raw ciphertext into this local context/level.
    ///
    /// This consumes the original storage without copying its words. Already
    /// bound storage cannot be retagged to another owner or level. Explicit adoption
    /// scans canonical residues once, including already bound mutable storage;
    /// later arithmetic checks provenance and geometry in O(1).
    ///
    /// # Correctness
    /// For raw storage the caller attests this context's actual ordered Q, NTT,
    /// BFV scale and intended secret. Canonical words do not prove these facts.
    /// # Errors
    /// Rejects unavailable/foreign levels, context provenance, incomplete shape,
    /// or noncanonical raw residues before assigning any local provenance.
    pub fn try_bind_ciphertext<C: primus_data::Data<Elem = u64>>(
        &self,
        mut ciphertext: BfvCiphertext<C>,
        level: usize,
    ) -> Result<BfvCiphertext<C>, crate::BfvCiphertextBindingError> {
        self.validate_canonical_ciphertext(&ciphertext, level)?;
        if ciphertext.binding.is_none() {
            ciphertext.binding = Some(crate::ciphertext::Binding::new(self, level));
        }
        Ok(ciphertext)
    }

    pub(crate) fn validate_canonical_ciphertext<C: primus_data::Data<Elem = u64>>(
        &self,
        ciphertext: &BfvCiphertext<C>,
        level: usize,
    ) -> Result<(), crate::BfvCiphertextBindingError> {
        self.check_ciphertext(ciphertext, level)?;
        let n = self.parameters.poly_length().get();
        let qs = self.codec(level).moduli_values();
        for (limb_index, (limb, &modulus)) in ciphertext
            .as_ref()
            .chunks_exact(n)
            .zip(qs.iter().cycle())
            .enumerate()
        {
            for (offset, &value) in limb.iter().enumerate() {
                if value >= modulus {
                    return Err(crate::BfvCiphertextBindingError::NonCanonical {
                        index: limb_index * n + offset,
                        value,
                        modulus,
                    });
                }
            }
        }
        Ok(())
    }

    /// Allocates an already-scaled degree-two ciphertext at a prepared level.
    ///
    /// The storage is intended for [`crate::advanced::BfvMultiplier`] output; it is not an
    /// unscaled integer tensor. Relinearize it before degree-one operations.
    ///
    /// # Panics
    /// Panics if the requested level is not prepared.
    #[must_use]
    pub fn new_quadratic_ciphertext(&self, level: usize) -> BfvQuadraticCiphertext<Vec<u64>> {
        BfvQuadraticCiphertext::bound(vec![0; 3 * self.rns_poly_len(level)], self, level)
    }

    /// Prepares public encryption at level zero, reusing the owned resources.
    ///
    /// # Errors
    /// Rejects a public key from another local context, or incompatible shape.
    /// Local provenance does not prove the actual secret or key-noise bound.
    pub fn public_key_encryptor<'a>(
        &'a self,
        key: &'a BfvPublicKey,
    ) -> Result<BfvPublicKeyEncryptor<'a>, BfvPublicKeyError> {
        BfvPublicKeyEncryptor::try_new(key, self)
    }
}
