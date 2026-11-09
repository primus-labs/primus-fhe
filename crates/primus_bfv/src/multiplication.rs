//! Prepared multiplication and the computation-only resources it owns.

mod auxiliary;
mod exact;
mod hps;
mod leveled;
mod words;

use primus_data::{Data, DataMut};
use primus_ntt::NttError;
use primus_rns::RnsError;

use crate::{
    BfvCiphertext, BfvContext, advanced::BfvQuadraticCiphertext, evaluation::BfvRelinearizer,
    keys::BfvRelinearizationKey,
};

use self::hps::HpsMultiplier;
pub use self::{exact::BfvMultiplier, leveled::BfvLeveledMultiplication};

/// Invalid level or computation-only basis for ordinary BFV multiplication.
#[derive(Debug, thiserror::Error)]
pub enum BfvMultiplyError {
    /// The requested ciphertext level was not prepared.
    #[error("BFV multiplication level {requested} is outside 0..{maximum}")]
    Level {
        /// Requested level.
        requested: usize,
        /// Number of prepared levels.
        maximum: usize,
    },
    /// Auxiliary moduli must be odd, below 2^62 and support a 2N-th root.
    #[error("invalid BFV multiplication auxiliary modulus {modulus} at index {index}")]
    AuxiliaryModulus {
        /// Position in the auxiliary basis.
        index: usize,
        /// Supplied modulus.
        modulus: u64,
    },
    /// An auxiliary modulus is not coprime to the ciphertext basis.
    #[error("BFV multiplication auxiliary modulus {auxiliary} is not coprime to {ciphertext}")]
    NonCoprime {
        /// Auxiliary modulus.
        auxiliary: u64,
        /// Ciphertext modulus.
        ciphertext: u64,
    },
    /// The auxiliary product must be strictly greater than NQ.
    #[error("BFV multiplication auxiliary product must be greater than NQ")]
    InsufficientAuxiliaryProduct,
    /// HPS's auxiliary product must exceed twice the ciphertext-prime count.
    #[error("BFV HPS multiplication auxiliary product must exceed twice the Q prime count")]
    InsufficientHpsAuxiliaryProduct,
    /// No further NTT primes were found in the automatic 60-bit search range.
    #[error("BFV multiplication could not prepare a sufficient automatic auxiliary basis")]
    AuxiliarySearchExhausted,
    /// An evaluation key is incompatible with the requested computation.
    #[error(transparent)]
    EvaluationKey(#[from] crate::keys::BfvEvaluationKeyError),
    /// A complete prepared storage length is not representable.
    #[error("BFV multiplication workspace length overflow")]
    LengthOverflow,
    /// Invalid auxiliary RNS basis.
    #[error(transparent)]
    Rns(#[from] RnsError),
    /// Invalid auxiliary NTT parameters.
    #[error(transparent)]
    Transform(#[from] NttError<u64>),
}

/// Arithmetic backend used by a prepared ordinary BFV multiplication request.
///
/// Both choices preserve the encryption modulus and native `c0+c1*s` phase.
/// Their scaled tensors can differ because HPSPOVERQ introduces a bounded
/// one-sided scaling error before tensoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BfvMultiplicationBackend {
    /// Centered exact integer tensor followed by exact `round(t*T/Q)`.
    Exact,
    /// One-sided P/Q scaling and an RNS tensor followed by `round(t*T/P)`.
    HpsPOverQ,
}

enum MultiplicationKernel<'a> {
    Exact(BfvMultiplier<'a>),
    HpsPOverQ(HpsMultiplier<'a>),
}

impl MultiplicationKernel<'_> {
    fn multiply_scaled_to(&mut self, lhs: &[u64], rhs: &[u64], output: &mut [u64]) {
        match self {
            Self::Exact(multiplier) => multiplier.multiply_scaled_to(lhs, rhs, output),
            Self::HpsPOverQ(multiplier) => multiplier.multiply_scaled_to(lhs, rhs, output),
        }
    }

    fn square_scaled_to(&mut self, input: &[u64], output: &mut [u64]) {
        match self {
            Self::Exact(multiplier) => multiplier.square_scaled_to(input, output),
            Self::HpsPOverQ(multiplier) => multiplier.square_scaled_to(input, output),
        }
    }
}

/// Prepared BFV multiplication followed by relinearization under one key.
///
/// The key determines the level. This owner keeps one scaled quadratic buffer,
/// the selected backend's multiplication resources and the relinearization scratch.
/// Online methods allocate nothing and return ordinary degree-one ciphertexts;
/// no modulus drop or noise-dependent policy is implicit. Bound operands must
/// use this local context and the key's level; explicit raw operands retain
/// caller-attested representation and actual-secret contracts.
///
/// # Correctness
/// Inputs must use the key's actual secret, ordered Q basis and NTT convention.
/// Numeric compatibility checks do not establish secret or representation
/// identity. The complete evaluated phase error must satisfy the level codec's
/// recovery bound; construction does not certify a circuit or its security.
pub struct BfvMultiplication<'a> {
    multiplier: MultiplicationKernel<'a>,
    relinearizer: BfvRelinearizer<'a>,
    quadratic: BfvQuadraticCiphertext<Vec<u64>>,
}

impl<'a> BfvMultiplication<'a> {
    /// Binds the key's level and automatically prepares computation-only P.
    ///
    /// # Errors
    /// Rejects incompatible key metadata, unsupported levels/transforms,
    /// overflowing storage or an exhausted auxiliary-prime search.
    pub fn try_new(
        context: &'a BfvContext,
        key: &'a BfvRelinearizationKey,
    ) -> Result<Self, BfvMultiplyError> {
        Self::try_with_backend(context, key, BfvMultiplicationBackend::Exact)
    }

    /// Binds the key's level and prepares only the selected backend's resources.
    ///
    /// HPSPOVERQ changes the multiplication rounding error, not the encryption
    /// or key modulus. Its one-sided P/Q scaling must be included in a complete
    /// circuit's error analysis; backend selection alone does not certify noise.
    /// Its automatic P product is at least `4*t²*N*L*(1+N*B)²`, using the
    /// configured secret sampler's hard magnitude bound B and Q prime count L.
    /// This bounds the additional epsilon term by `Q/(8t)` when the actual
    /// secret satisfies that support. The centered-wrap, input-phase,
    /// plaintext-growth and relinearization errors require separate budgets.
    ///
    /// # Errors
    /// Rejects incompatible keys, unsupported levels or transforms, overflowing
    /// geometry, or an exhausted auxiliary-prime search.
    pub fn try_with_backend(
        context: &'a BfvContext,
        key: &'a BfvRelinearizationKey,
        backend: BfvMultiplicationBackend,
    ) -> Result<Self, BfvMultiplyError> {
        Self::prepare(context, key, backend, None)
    }

    /// Prepares one backend with explicit ordered computation-only P moduli.
    ///
    /// Exact requires P>NQ; HPSPOVERQ uses its own one-sided scaling resources
    /// and does not reconstruct the complete integer tensor. It requires P>2L,
    /// where L is the Q prime count, to bound its centered wrap correction.
    /// This is an arithmetic condition, not a complete noise budget. The requested
    /// auxiliary basis never extends an encryption or evaluation-key modulus.
    ///
    /// # Errors
    /// Rejects incompatible key metadata, unsupported or noncoprime auxiliary
    /// primes, insufficient auxiliary product for the selected backend,
    /// overflowing storage, or unsupported transforms.
    pub fn try_with_backend_and_auxiliary_moduli(
        context: &'a BfvContext,
        key: &'a BfvRelinearizationKey,
        backend: BfvMultiplicationBackend,
        auxiliary_moduli: &[u64],
    ) -> Result<Self, BfvMultiplyError> {
        Self::prepare(context, key, backend, Some(auxiliary_moduli))
    }

    fn prepare(
        context: &'a BfvContext,
        key: &'a BfvRelinearizationKey,
        backend: BfvMultiplicationBackend,
        auxiliary_moduli: Option<&[u64]>,
    ) -> Result<Self, BfvMultiplyError> {
        let level = key.level();
        let relinearizer = BfvRelinearizer::try_new(context, key)?;
        let multiplier =
            match backend {
                BfvMultiplicationBackend::Exact => MultiplicationKernel::Exact(
                    BfvMultiplier::prepare(context, level, auxiliary_moduli)?,
                ),
                BfvMultiplicationBackend::HpsPOverQ => MultiplicationKernel::HpsPOverQ(
                    HpsMultiplier::prepare(context, level, auxiliary_moduli)?,
                ),
            };
        Ok(Self {
            multiplier,
            relinearizer,
            quadratic: context.new_quadratic_ciphertext(level),
        })
    }

    /// Returns the prepared arithmetic backend.
    #[must_use]
    pub fn backend(&self) -> BfvMultiplicationBackend {
        match self.multiplier {
            MultiplicationKernel::Exact(_) => BfvMultiplicationBackend::Exact,
            MultiplicationKernel::HpsPOverQ(_) => BfvMultiplicationBackend::HpsPOverQ,
        }
    }

    /// Borrows the selected backend's ordered computation-only auxiliary basis.
    #[must_use]
    pub fn auxiliary_moduli(&self) -> &[u64] {
        match &self.multiplier {
            MultiplicationKernel::Exact(multiplier) => multiplier.auxiliary_moduli(),
            MultiplicationKernel::HpsPOverQ(multiplier) => multiplier.auxiliary_moduli(),
        }
    }

    /// Writes the scaled and relinearized product, reusing prepared storage.
    ///
    /// # Panics
    /// Recorded context/level conflicts and all complete input/output lengths
    /// are checked before output or scratch writes. A transform panic can leave
    /// intermediate scratch modified.
    pub fn multiply_to<A, B, C>(
        &mut self,
        lhs: &BfvCiphertext<A>,
        rhs: &BfvCiphertext<B>,
        output: &mut BfvCiphertext<C>,
    ) where
        A: Data<Elem = u64>,
        B: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        self.check_ciphertext(lhs);
        self.check_ciphertext(rhs);
        self.check_ciphertext(output);
        self.multiplier
            .multiply_scaled_to(lhs.as_ref(), rhs.as_ref(), self.quadratic.as_mut());
        self.relinearizer
            .relinearize_validated_to(&self.quadratic, output);
    }

    /// Writes the scaled and relinearized square with prepared storage.
    ///
    /// Inherits [`Self::multiply_to`]'s correctness and prewrite checks.
    pub fn square_to<A, B>(&mut self, input: &BfvCiphertext<A>, output: &mut BfvCiphertext<B>)
    where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        self.check_ciphertext(input);
        self.check_ciphertext(output);
        self.multiplier
            .square_scaled_to(input.as_ref(), self.quadratic.as_mut());
        self.relinearizer
            .relinearize_validated_to(&self.quadratic, output);
    }

    /// Squares and relinearizes in place without another ciphertext allocation.
    ///
    /// The input is read completely into internal quadratic storage before the
    /// first write to it. Inherits [`Self::multiply_to`]'s representation contract.
    ///
    /// # Panics
    /// Rejects recorded context/level conflicts or incorrect lengths before
    /// output or scratch writes.
    pub fn square_assign<A>(&mut self, input: &mut BfvCiphertext<A>)
    where
        A: DataMut<Elem = u64>,
    {
        self.check_ciphertext(input);
        self.multiplier
            .square_scaled_to(input.as_ref(), self.quadratic.as_mut());
        self.relinearizer
            .relinearize_validated_to(&self.quadratic, input);
    }

    fn check_ciphertext<C: Data<Elem = u64>>(&self, ciphertext: &BfvCiphertext<C>) {
        check_ciphertext(
            self.relinearizer.context(),
            self.relinearizer.external_level(),
            ciphertext,
        );
    }
}

fn check_ciphertext<C: Data<Elem = u64>>(
    context: &BfvContext,
    level: usize,
    ciphertext: &BfvCiphertext<C>,
) {
    ciphertext.check_binding(context, level);
    assert_eq!(
        ciphertext.as_ref().len(),
        2 * context.rns_poly_len(level),
        "BFV ciphertext length mismatch"
    );
}
