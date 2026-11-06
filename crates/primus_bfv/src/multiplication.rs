use primus_data::{Data, DataMut};

use crate::multiply::hps::HpsMultiplier;

use crate::{
    BfvCiphertext, BfvContext, BfvMultiplier, BfvMultiplyError, BfvQuadraticCiphertext,
    BfvRelinearizationKey, BfvRelinearizer,
};

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
        let relinearizer = BfvRelinearizer::try_new(context, key)?;
        let multiplier = match backend {
            BfvMultiplicationBackend::Exact => MultiplicationKernel::Exact(
                BfvMultiplier::try_with_default_basis(context, key.level())?,
            ),
            BfvMultiplicationBackend::HpsPOverQ => MultiplicationKernel::HpsPOverQ(
                HpsMultiplier::try_with_default_basis(context, key.level())?,
            ),
        };
        Ok(Self {
            multiplier,
            relinearizer,
            quadratic: context.new_quadratic_ciphertext(key.level()),
        })
    }

    /// Prepares the exact backend with explicitly selected computation-only P.
    ///
    /// Inherits [`BfvMultiplier::try_new`]'s exact P>NQ and transform
    /// requirements. It never changes the encryption or key modulus.
    ///
    /// # Errors
    /// See [`Self::try_with_backend_and_auxiliary_moduli`].
    pub fn try_with_auxiliary_moduli(
        context: &'a BfvContext,
        key: &'a BfvRelinearizationKey,
        auxiliary_moduli: &[u64],
    ) -> Result<Self, BfvMultiplyError> {
        Self::try_with_backend_and_auxiliary_moduli(
            context,
            key,
            BfvMultiplicationBackend::Exact,
            auxiliary_moduli,
        )
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
        let relinearizer = BfvRelinearizer::try_new(context, key)?;
        let multiplier =
            match backend {
                BfvMultiplicationBackend::Exact => MultiplicationKernel::Exact(
                    BfvMultiplier::try_new(context, key.level(), auxiliary_moduli)?,
                ),
                BfvMultiplicationBackend::HpsPOverQ => MultiplicationKernel::HpsPOverQ(
                    HpsMultiplier::try_new(context, key.level(), auxiliary_moduli)?,
                ),
            };
        Ok(Self {
            multiplier,
            relinearizer,
            quadratic: context.new_quadratic_ciphertext(key.level()),
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
    /// are checked before output or scratch writes. A transform panic can leave intermediate scratch modified.
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
        lhs.check_binding(
            self.relinearizer.context(),
            self.relinearizer.external_level(),
        );
        rhs.check_binding(
            self.relinearizer.context(),
            self.relinearizer.external_level(),
        );
        output.check_binding(
            self.relinearizer.context(),
            self.relinearizer.external_level(),
        );
        self.validate_output(output.as_ref());
        match &mut self.multiplier {
            MultiplicationKernel::Exact(multiplier) => {
                multiplier.multiply_to(lhs, rhs, &mut self.quadratic)
            }
            MultiplicationKernel::HpsPOverQ(multiplier) => {
                multiplier.multiply_to(lhs, rhs, &mut self.quadratic)
            }
        }
        self.relinearizer.relinearize_to(&self.quadratic, output);
    }

    /// Writes the scaled and relinearized square with prepared storage.
    ///
    /// Inherits [`Self::multiply_to`]'s correctness and prewrite checks.
    pub fn square_to<A, B>(&mut self, input: &BfvCiphertext<A>, output: &mut BfvCiphertext<B>)
    where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        input.check_binding(
            self.relinearizer.context(),
            self.relinearizer.external_level(),
        );
        output.check_binding(
            self.relinearizer.context(),
            self.relinearizer.external_level(),
        );
        self.validate_output(output.as_ref());
        match &mut self.multiplier {
            MultiplicationKernel::Exact(multiplier) => {
                multiplier.square_to(input, &mut self.quadratic)
            }
            MultiplicationKernel::HpsPOverQ(multiplier) => {
                multiplier.square_to(input, &mut self.quadratic)
            }
        }
        self.relinearizer.relinearize_to(&self.quadratic, output);
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
        input.check_binding(
            self.relinearizer.context(),
            self.relinearizer.external_level(),
        );
        match &mut self.multiplier {
            MultiplicationKernel::Exact(multiplier) => {
                multiplier.square_to(input, &mut self.quadratic)
            }
            MultiplicationKernel::HpsPOverQ(multiplier) => {
                multiplier.square_to(input, &mut self.quadratic)
            }
        }
        self.relinearizer.relinearize_to(&self.quadratic, input);
    }

    fn validate_output(&self, output: &[u64]) {
        assert_eq!(output.len(), self.quadratic.as_ref().len() / 3 * 2);
    }
}
