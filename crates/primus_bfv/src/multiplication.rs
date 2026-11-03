use primus_data::{Data, DataMut};

use crate::{
    BfvCiphertext, BfvContext, BfvMultiplier, BfvMultiplyError, BfvQuadraticCiphertext,
    BfvRelinearizationKey, BfvRelinearizer,
};

/// Prepared BFV multiplication followed by relinearization under one key.
///
/// The key determines the level. This owner keeps one scaled quadratic buffer,
/// the exact integer multiplication resources and the relinearization scratch.
/// Online methods allocate nothing and return ordinary degree-one ciphertexts;
/// no modulus drop or noise-dependent policy is implicit.
///
/// # Correctness
/// Inputs must use the key's actual secret, ordered Q basis and NTT convention.
/// Numeric compatibility checks do not establish secret or representation
/// identity. The complete evaluated phase error must satisfy the level codec's
/// recovery bound; construction does not certify a circuit or its security.
pub struct BfvMultiplication<'a> {
    multiplier: BfvMultiplier<'a>,
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
        let relinearizer = BfvRelinearizer::try_new(context, key)?;
        Ok(Self {
            multiplier: BfvMultiplier::try_with_default_basis(context, key.level())?,
            relinearizer,
            quadratic: context.new_quadratic_ciphertext(key.level()),
        })
    }

    /// Prepares the same request with explicitly selected computation-only P.
    ///
    /// This advanced entry uses [`BfvMultiplier::try_new`]'s exact P>NQ and
    /// transform requirements. It never changes the encryption/key modulus.
    ///
    /// # Errors
    /// Rejects incompatible keys or any invalid explicit auxiliary basis before
    /// the first online request; see [`Self::try_new`] and [`BfvMultiplier::try_new`].
    pub fn try_with_auxiliary_moduli(
        context: &'a BfvContext,
        key: &'a BfvRelinearizationKey,
        auxiliary_moduli: &[u64],
    ) -> Result<Self, BfvMultiplyError> {
        let relinearizer = BfvRelinearizer::try_new(context, key)?;
        Ok(Self {
            multiplier: BfvMultiplier::try_new(context, key.level(), auxiliary_moduli)?,
            relinearizer,
            quadratic: context.new_quadratic_ciphertext(key.level()),
        })
    }

    /// Writes the scaled and relinearized product, reusing prepared storage.
    ///
    /// # Panics
    /// All complete input/output lengths are checked before output or scratch
    /// writes. A transform panic can leave intermediate scratch modified.
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
        self.validate_output(output.as_ref());
        self.multiplier.multiply_to(lhs, rhs, &mut self.quadratic);
        self.relinearizer.relinearize_to(&self.quadratic, output);
    }

    /// Writes the scaled and relinearized square with one lifted input.
    ///
    /// Inherits [`Self::multiply_to`]'s correctness and prewrite checks.
    pub fn square_to<A, B>(&mut self, input: &BfvCiphertext<A>, output: &mut BfvCiphertext<B>)
    where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        self.validate_output(output.as_ref());
        self.multiplier.square_to(input, &mut self.quadratic);
        self.relinearizer.relinearize_to(&self.quadratic, output);
    }

    /// Squares and relinearizes in place without another ciphertext allocation.
    ///
    /// The input is read completely into internal quadratic storage before the
    /// first write to it. Inherits [`Self::multiply_to`]'s representation contract.
    ///
    /// # Panics
    /// Rejects an incorrect complete length before output or scratch writes.
    pub fn square_assign<A>(&mut self, input: &mut BfvCiphertext<A>)
    where
        A: DataMut<Elem = u64>,
    {
        self.multiplier.square_to(input, &mut self.quadratic);
        self.relinearizer.relinearize_to(&self.quadratic, input);
    }

    fn validate_output(&self, output: &[u64]) {
        assert_eq!(output.len(), self.quadratic.as_ref().len() / 3 * 2);
    }
}
