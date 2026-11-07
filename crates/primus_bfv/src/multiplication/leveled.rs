use primus_data::{Data, DataMut};

use crate::working_basis::WorkingBasis;
use crate::{
    BfvCiphertext, BfvContext, advanced::BfvQuadraticCiphertext, evaluation::BfvRelinearizer,
    keys::BfvRelinearizationKey,
};

use super::{BfvMultiplyError, check_ciphertext, hps::HpsMultiplier};

/// HPSPOVERQLEVELED multiplication with a smaller internal working basis.
///
/// Inputs and outputs retain the ordered external Q basis. Each input component
/// is first exactly rounded from Q to its prepared prefix Q_l. HPSPOVERQ and
/// relinearization then operate in Q_l, using a key generated at that actual
/// level. Finally every component is multiplied by D=Q/Q_l and embedded back in
/// Q: retained limbs are scaled by D, and omitted limbs are zero. This is the
/// double-rounded Algorithm3 variant, rather than the fused right-input
/// conversion optimization. It does not permanently lower a ciphertext's level.
///
/// Mutable buffers belong to this operation; NTT tables and key columns are
/// borrowed. Online methods allocate nothing. The working basis is explicit:
/// no noise estimate, remaining-depth guess or empirical cushion is inferred.
/// Bound input/output storage keeps this context and the external level; the
/// internal working level is never used to retag the caller's ciphertext.
///
/// # Correctness
/// Inputs must use the key's actual coefficient secret, external ordered Q
/// basis and NTT convention. Numeric compatibility does not establish those
/// identities. A complete circuit budget must include both input rounding
/// errors, the working-level HPS residual and centered wrap, native key-switch
/// error, their final multiplication by D, and fixed-Delta restoration drift.
/// Construction prepares arithmetic resources, not a noise/security certificate.
pub struct BfvLeveledMultiplication<'a> {
    basis: WorkingBasis<'a>,
    multiplier: HpsMultiplier<'a>,
    relinearizer: BfvRelinearizer<'a>,
    lhs: BfvCiphertext<Vec<u64>>,
    rhs: BfvCiphertext<Vec<u64>>,
    quadratic: BfvQuadraticCiphertext<Vec<u64>>,
}

impl<'a> BfvLeveledMultiplication<'a> {
    /// Prepares Algorithm3 with the key's actual level as the working level.
    ///
    /// `external_level <= key.level()`. Equality degenerates to ordinary
    /// HPSPOVERQ. The automatic computation-only P follows the working-level
    /// HPS epsilon budget; it does not certify the complete operation's error.
    ///
    /// # Errors
    /// Rejects an unavailable or reversed level pair, incompatible key metadata,
    /// overflowing geometry or an exhausted automatic auxiliary-prime search.
    pub fn try_new(
        context: &'a BfvContext,
        external_level: usize,
        key: &'a BfvRelinearizationKey,
    ) -> Result<Self, BfvMultiplyError> {
        Self::prepare(context, external_level, key, None)
    }

    /// Prepares the same operation with an explicit computation-only P basis.
    ///
    /// P must satisfy the working-level HPS arithmetic conditions; it is
    /// unrelated to a Hybrid evaluation key's auxiliary basis. Neither P nor
    /// Q_l changes the external encryption parameters or ciphertext length.
    ///
    /// # Errors
    /// Inherits [`Self::try_new`]'s level/key checks. Also rejects unsupported,
    /// repeated or noncoprime P moduli and insufficient auxiliary product.
    pub fn try_with_auxiliary_moduli(
        context: &'a BfvContext,
        external_level: usize,
        key: &'a BfvRelinearizationKey,
        auxiliary_moduli: &[u64],
    ) -> Result<Self, BfvMultiplyError> {
        Self::prepare(context, external_level, key, Some(auxiliary_moduli))
    }

    fn prepare(
        context: &'a BfvContext,
        external_level: usize,
        key: &'a BfvRelinearizationKey,
        auxiliary_moduli: Option<&[u64]>,
    ) -> Result<Self, BfvMultiplyError> {
        let working_level = key.level();
        let basis = WorkingBasis::try_new(context, external_level, working_level)?;
        let relinearizer = BfvRelinearizer::try_new(context, key)?;
        let multiplier = HpsMultiplier::prepare(context, working_level, auxiliary_moduli)?;
        Ok(Self {
            basis,
            multiplier,
            relinearizer,
            lhs: context.new_ciphertext(working_level),
            rhs: context.new_ciphertext(working_level),
            quadratic: context.new_quadratic_ciphertext(working_level),
        })
    }

    /// External input/output level, preserved across every request.
    #[must_use]
    pub fn external_level(&self) -> usize {
        self.basis.external_level()
    }

    /// Actual internal HPS and relinearization-key level.
    #[must_use]
    pub fn working_level(&self) -> usize {
        self.basis.working_level()
    }

    /// Ordered computation-only P moduli used by the internal HPS operation.
    #[must_use]
    pub fn auxiliary_moduli(&self) -> &[u64] {
        self.multiplier.auxiliary_moduli()
    }

    /// Writes a degree-one product in the complete external Q basis.
    ///
    /// # Panics
    /// Rejects recorded context/external-level conflicts and incorrect complete
    /// input/output lengths before any scratch or output writes. Transform failures
    /// may partially modify scratch or output.
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
        self.basis
            .shrink_ciphertext_to(lhs.as_ref(), self.lhs.as_mut());
        self.basis
            .shrink_ciphertext_to(rhs.as_ref(), self.rhs.as_mut());
        self.multiplier.multiply_scaled_to(
            self.lhs.as_ref(),
            self.rhs.as_ref(),
            self.quadratic.as_mut(),
        );
        self.finish(output.as_mut());
    }

    /// Writes a relinearized square while shrinking the input only once.
    ///
    /// Inherits [`Self::multiply_to`]'s external representation and error
    /// contract. HPS still uses its actual asymmetric working-level square.
    ///
    /// # Panics
    /// Rejects recorded context/external-level conflicts and incorrect complete
    /// input/output lengths before scratch or output writes.
    pub fn square_to<A, B>(&mut self, input: &BfvCiphertext<A>, output: &mut BfvCiphertext<B>)
    where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        self.check_ciphertext(input);
        self.check_ciphertext(output);
        self.square_into_working_basis(input.as_ref());
        self.finish(output.as_mut());
    }

    /// Squares in place, retaining the complete external Q storage.
    ///
    /// The original input is fully consumed into prepared scratch before the
    /// first write. Inherits [`Self::square_to`]'s mathematical contract.
    ///
    /// # Panics
    /// Rejects recorded context/external-level conflicts or incorrect lengths
    /// before any writes.
    pub fn square_assign<A>(&mut self, input: &mut BfvCiphertext<A>)
    where
        A: DataMut<Elem = u64>,
    {
        self.check_ciphertext(input);
        self.square_into_working_basis(input.as_ref());
        self.finish(input.as_mut());
    }

    fn square_into_working_basis(&mut self, input: &[u64]) {
        self.basis.shrink_ciphertext_to(input, self.lhs.as_mut());
        self.multiplier
            .square_scaled_to(self.lhs.as_ref(), self.quadratic.as_mut());
    }

    fn finish(&mut self, output: &mut [u64]) {
        self.relinearizer
            .relinearize_validated_to(&self.quadratic, &mut self.lhs);
        self.basis.restore_ciphertext_to(self.lhs.as_ref(), output);
    }

    fn check_ciphertext<C: Data<Elem = u64>>(&self, ciphertext: &BfvCiphertext<C>) {
        check_ciphertext(
            self.relinearizer.context(),
            self.basis.external_level(),
            ciphertext,
        );
    }
}
