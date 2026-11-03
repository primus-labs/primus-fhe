use crate::{
    BgvCiphertext, BgvParameters, BgvPublicKey, BgvPublicKeyEncryptor, BgvPublicKeyError,
    BgvQuadraticCiphertext,
};
use primus_integer::BigUint;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttError, U64DcrtTable};
use primus_poly::Polynomial;
use primus_reduce::Reduce;
use primus_rns::RNSBase;

/// Unsupported transforms or number of requested ordered-prefix levels.
#[derive(Debug, thiserror::Error)]
pub enum BgvContextError {
    /// A ciphertext modulus does not support the full-ring transform.
    #[error(transparent)]
    Transform(#[from] NttError<u64>),
    /// At least one level and at most one per ciphertext prime are supported.
    #[error("BGV level count {requested} is outside 1..={maximum}")]
    LevelCount {
        /// Requested level count, including the highest level.
        requested: usize,
        /// Number of primes in the highest basis.
        maximum: usize,
    },
}

struct LowerLevel {
    base: RNSBase<u64, BarrettModulus<u64>>,
    half_q: Vec<u64>,
    q_mod_p: u64,
}

/// One immutable owner of full-ring BGV parameters and their DCRT NTT table.
/// Clients, evaluators and public encryptors borrow this owner without cloning.
pub struct BgvContext {
    parameters: BgvParameters,
    table: U64DcrtTable,
    lower_levels: Vec<LowerLevel>,
}

impl BgvContext {
    /// Consumes prepared parameters and checks each full-ring NTT modulus.
    ///
    /// # Correctness
    /// Ciphertext moduli must be prime. Transform preparation checks its numeric
    /// root/size requirements; it does not certify primality. Coefficient p need
    /// not be prime; batching has its own stronger plaintext-field requirements.
    ///
    /// # Errors
    /// Rejects a basis incompatible with the requested full polynomial length.
    pub fn try_new(parameters: BgvParameters) -> Result<Self, BgvContextError> {
        Self::try_with_levels(parameters, 1)
    }

    /// Prepares a full-Q level and the requested number of ordered prefixes.
    ///
    /// Level `l` omits the last `l` primes. Only the highest level owns sampling
    /// state; lower levels own their distinct CRT bases and recovery constants.
    /// The full-ring NTT tables and the client's secret are borrowed by prefix.
    /// Lower-level preparation does not establish an evaluated noise bound.
    ///
    /// # Errors
    /// Rejects an unsupported count or transform. The prime-modulus correctness
    /// precondition is the same as [`Self::try_new`]'s.
    pub fn try_with_levels(
        parameters: BgvParameters,
        level_count: usize,
    ) -> Result<Self, BgvContextError> {
        let maximum = parameters.base_q().moduli_count();
        if level_count == 0 || level_count > maximum {
            return Err(BgvContextError::LevelCount {
                requested: level_count,
                maximum,
            });
        }
        let mut lower_levels = Vec::with_capacity(level_count - 1);
        for level in 1..level_count {
            let base = RNSBase::new(&parameters.base_q().moduli()[..maximum - level])
                .expect("a nonempty prefix of a valid RNS basis is valid");
            let mut half_q = base.moduli_product().0.to_vec();
            BigUint(&mut half_q[..]).right_shift_assign(1);
            let q_mod_p = parameters.plain_modulus().reduce(base.moduli_product().0);
            lower_levels.push(LowerLevel {
                base,
                half_q,
                q_mod_p,
            });
        }
        let table = U64DcrtTable::new(parameters.poly_length(), parameters.base_q().moduli())?;
        Ok(Self {
            parameters,
            table,
            lower_levels,
        })
    }

    /// Borrows the unique parameters and sampler state.
    #[must_use]
    pub fn parameters(&self) -> &BgvParameters {
        &self.parameters
    }

    /// Borrows the full ciphertext-ring transform table.
    #[must_use]
    pub fn table(&self) -> &U64DcrtTable {
        &self.table
    }

    /// Returns the number of prepared levels, including level zero.
    #[must_use]
    pub fn level_count(&self) -> usize {
        self.lower_levels.len() + 1
    }

    /// Borrows the ordered ciphertext basis at an explicit prepared level.
    ///
    /// # Panics
    /// Rejects an unprepared level.
    #[must_use]
    pub fn base_q(&self, level: usize) -> &RNSBase<u64, BarrettModulus<u64>> {
        if level == 0 {
            self.parameters.base_q()
        } else {
            &self
                .lower_levels
                .get(level - 1)
                .expect("invalid BGV level")
                .base
        }
    }

    /// Returns one complete modulus-major polynomial length at a level.
    ///
    /// # Panics
    /// Rejects an unprepared level.
    #[must_use]
    pub fn rns_poly_len(&self, level: usize) -> usize {
        self.base_q(level).moduli_count() * self.parameters.poly_length().get()
    }

    /// Allocates a zeroed full-ring coefficient plaintext using this context's N.
    #[must_use]
    pub fn new_plaintext(&self) -> Polynomial<Vec<u64>> {
        Polynomial::zero(self.parameters.poly_length().get())
    }

    /// Prepares full-ring slot packing using this context's N and plaintext p.
    ///
    /// The returned encoder owns its one plaintext transform table; the context
    /// does not cache another copy. Explicit n<N packing remains available through
    /// [`primus_encoding::BatchingEncoder::try_new`].
    /// # Correctness
    /// p must be prime; see [`primus_encoding::BatchingEncoder`].
    /// # Errors
    /// Returns the encoder's plaintext transform or missing-root error. A context
    /// supporting coefficient arithmetic need not support full-ring batching.
    #[cfg(feature = "batching")]
    pub fn batching_encoder(&self) -> Result<primus_encoding::BatchingEncoder, NttError<u64>> {
        primus_encoding::BatchingEncoder::try_new(
            self.parameters.poly_length(),
            self.parameters.plain_modulus(),
        )
    }

    /// Allocates a zeroed native degree-one ciphertext at a prepared level.
    ///
    /// # Panics
    /// Rejects an unprepared level.
    #[must_use]
    pub fn new_ciphertext(&self, level: usize) -> BgvCiphertext<Vec<u64>> {
        BgvCiphertext::zero(2 * self.rns_poly_len(level))
    }

    /// Allocates a degree-two tensor output with phase `c0+c1*s+c2*s²`.
    ///
    /// # Panics
    /// Rejects an unprepared level or overflowing storage length.
    #[must_use]
    pub fn new_quadratic_ciphertext(&self, level: usize) -> BgvQuadraticCiphertext<Vec<u64>> {
        BgvQuadraticCiphertext::zero(
            self.rns_poly_len(level)
                .checked_mul(3)
                .expect("BGV quadratic length overflow"),
        )
    }

    pub(crate) fn half_q(&self, level: usize) -> &[u64] {
        if level == 0 {
            &self.parameters.half_q
        } else {
            &self
                .lower_levels
                .get(level - 1)
                .expect("invalid BGV level")
                .half_q
        }
    }

    pub(crate) fn q_mod_p(&self, level: usize) -> u64 {
        if level == 0 {
            self.parameters.q_mod_p
        } else {
            self.lower_levels
                .get(level - 1)
                .expect("invalid BGV level")
                .q_mod_p
        }
    }

    /// Binds a native public key and allocates one erasing ephemeral workspace.
    ///
    /// # Errors
    /// Rejects different polynomial geometry, p or ordered Q. Actual secret and
    /// NTT root/evaluation identity remain caller contracts.
    pub fn public_key_encryptor<'a>(
        &'a self,
        key: &'a BgvPublicKey,
    ) -> Result<BgvPublicKeyEncryptor<'a>, BgvPublicKeyError> {
        BgvPublicKeyEncryptor::try_new(key, self)
    }
}
