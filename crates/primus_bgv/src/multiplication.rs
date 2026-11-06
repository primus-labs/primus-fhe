use crate::evaluator::{square_to, tensor_to};
use crate::{
    BgvCiphertext, BgvContext, BgvEvaluationKeyError, BgvQuadraticCiphertext,
    BgvRelinearizationKey, BgvRelinearizer,
};
use primus_data::{Data, DataMut};

/// Prepared ciphertext multiplication followed by native BGV relinearization.
///
/// The key selects one prepared modulus level. This request borrows the context
/// and key, and owns one reusable quadratic buffer plus relinearization scratch.
/// It applies no BFV scaling, prime drop or automatic noise policy. The output
/// plaintext correction is the product of the two input corrections modulo p.
pub struct BgvMultiplication<'a> {
    context: &'a BgvContext,
    level: usize,
    quadratic: BgvQuadraticCiphertext<Vec<u64>>,
    relinearizer: BgvRelinearizer<'a>,
}

impl<'a> BgvMultiplication<'a> {
    /// Checks the key's exact context and level, then prepares reusable storage.
    ///
    /// # Errors
    /// Rejects a foreign-context key, including numerically identical contexts.
    pub fn try_new(
        context: &'a BgvContext,
        key: &'a BgvRelinearizationKey,
    ) -> Result<Self, BgvEvaluationKeyError> {
        let level = key.level();
        let relinearizer = BgvRelinearizer::try_new(context, key)?;
        Ok(Self {
            context,
            level,
            quadratic: context.new_quadratic_ciphertext(level),
            relinearizer,
        })
    }

    /// Writes the product as a degree-one ciphertext without online allocation.
    ///
    /// # Correctness
    /// Inputs use the key's actual secret and the context's canonical ordered
    /// level basis and NTT convention. The complete product and relinearization
    /// error must remain in the centered Q recovery interval.
    /// # Panics
    /// Recorded context/level mismatches and incorrect lengths are rejected before writes.
    /// Arithmetic failure may partially overwrite output and internal scratch.
    pub fn multiply_to<A, B, C>(
        &mut self,
        lhs: &BgvCiphertext<A>,
        rhs: &BgvCiphertext<B>,
        output: &mut BgvCiphertext<C>,
    ) where
        A: Data<Elem = u64>,
        B: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        self.validate_output(output);
        tensor_to(self.context, self.level, lhs, rhs, &mut self.quadratic);
        self.relinearizer.relinearize_to(&self.quadratic, output);
    }

    /// Writes the relinearized square, reusing the three-product square kernel.
    /// The representation, recovery-bound and panic contracts are
    /// [`Self::multiply_to`]'s. Prepared calls allocate nothing.
    pub fn square_to<A, B>(&mut self, input: &BgvCiphertext<A>, output: &mut BgvCiphertext<B>)
    where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        self.validate_output(output);
        square_to(self.context, self.level, input, &mut self.quadratic);
        self.relinearizer.relinearize_to(&self.quadratic, output);
    }

    /// Replaces a ciphertext with its relinearized square without allocating.
    /// The input is fully consumed into internal quadratic scratch before output
    /// writes. See [`Self::multiply_to`] for representation and phase bounds.
    /// # Panics
    /// Rejects recorded context/level or complete length mismatches before writes; failure may
    /// partially overwrite internal scratch or the ciphertext.
    pub fn square_assign<A: DataMut<Elem = u64>>(&mut self, input: &mut BgvCiphertext<A>) {
        square_to(self.context, self.level, input, &mut self.quadratic);
        self.relinearizer.relinearize_to(&self.quadratic, input);
    }

    fn validate_output<B: Data<Elem = u64>>(&self, output: &BgvCiphertext<B>) {
        output.check_binding(self.context, self.level);
        assert_eq!(
            output.as_ref().len(),
            2 * self.context.rns_poly_len(self.level),
            "BGV multiplication output length mismatch"
        );
    }
}
