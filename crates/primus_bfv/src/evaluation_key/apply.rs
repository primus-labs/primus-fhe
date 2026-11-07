//! Prepare and apply a native key to its specific ciphertext role.
use primus_data::{Data, DataMut};
use primus_ntt::NttAutomorphismPermutation;
use primus_poly::DcrtPolynomial;

use crate::{BfvCiphertext, BfvContext, advanced::BfvQuadraticCiphertext};

use super::{
    BfvEvaluationKeyError,
    material::{BfvAutomorphismKey, BfvKeySwitchingKey, BfvRelinearizationKey},
    working::WorkingKeyProduct,
};

/// Reusable s²-to-s relinearization at one BFV prefix level.
pub struct BfvRelinearizer<'a> {
    product: WorkingKeyProduct<'a>,
}

impl<'a> BfvRelinearizer<'a> {
    pub(crate) fn context(&self) -> &'a BfvContext {
        self.product.context()
    }
    pub(crate) fn external_level(&self) -> usize {
        self.product.external_level()
    }

    /// Binds the key's level and numerical metadata before allocating reusable scratch.
    /// # Errors
    /// Rejects an unprepared key level or a foreign local generating context.
    /// Foreign numerical mismatches retain their detailed diagnostics.
    pub fn try_new(
        context: &'a BfvContext,
        key: &'a BfvRelinearizationKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        Self::try_with_working_level(context, key.level(), key)
    }

    /// Prepares a temporary smaller basis for the switched quadratic component.
    ///
    /// The key's actual level is the internal working level; `external_level`
    /// is the unchanged input/output basis. Only c2 is rounded down, its native
    /// key product is multiplied by D=Q/Q_l and zero-extended, then the original
    /// external c0/c1 are added. This is not a permanent ciphertext modulus drop.
    ///
    /// # Correctness
    /// The key encrypts the same actual s² under s at its working level. If A
    /// bounds native working-key error and H bounds ||s||_1, the extra error is
    /// at most D*(A+H²/2); budget it in addition to the input quadratic phase.
    /// Metadata does not certify these bounds or a circuit's recoverability.
    /// # Errors
    /// Rejects unavailable levels, a working basis larger than the external
    /// basis, or an incompatible actual key. Equal levels retain the old path.
    pub fn try_with_working_level(
        context: &'a BfvContext,
        external_level: usize,
        key: &'a BfvRelinearizationKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        Ok(Self {
            product: WorkingKeyProduct::try_new(context, external_level, &key.key)?,
        })
    }

    /// Writes `[t0+P0,t1+P1]` for P encrypting t2*s².
    ///
    /// The input has already undergone BFV scale-and-round. A computation-only
    /// raw tensor is private to the multiplier and cannot be supplied here.
    ///
    /// # Correctness
    /// Input components are canonical residues using this actual secret,
    /// ordered level basis and NTT convention.
    /// Decomposition residual, key noise and Hybrid ModDown rounding consume
    /// the BFV phase-error margin;
    /// the complete evaluated error must satisfy the level codec recovery bound.
    /// # Panics
    /// Rejects recorded context/level conflicts and incomplete storage before
    /// writes. Prepared calls
    /// allocate nothing; transform/RNS failure may partially overwrite scratch/output.
    pub fn relinearize_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BfvQuadraticCiphertext<A>,
        output: &mut BfvCiphertext<B>,
    ) {
        input.check_binding(self.product.context(), self.product.external_level());
        output.check_binding(self.product.context(), self.product.external_level());
        let len = self.product.poly_len();
        assert_eq!(
            input.as_ref().len(),
            3 * len,
            "BFV quadratic length mismatch"
        );
        assert_eq!(output.as_ref().len(), 2 * len, "BFV output length mismatch");
        self.relinearize_validated_to(input, output);
    }

    // Compound multiplication has already checked the output and owns the
    // scaled tensor at this exact context and level.
    pub(crate) fn relinearize_validated_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BfvQuadraticCiphertext<A>,
        output: &mut BfvCiphertext<B>,
    ) {
        let len = self.product.poly_len();
        let (t0, rest) = input.as_ref().split_at(len);
        let (t1, t2) = rest.split_at(len);
        self.product.product_to(t2, None, output.as_mut());
        let (c0, c1) = output.as_mut().split_at_mut(len);
        let n = self.product.context().parameters().poly_length().get();
        let moduli = self.product.moduli();
        DcrtPolynomial(c0).add_assign(&DcrtPolynomial(t0), n, moduli);
        DcrtPolynomial(c1).add_assign(&DcrtPolynomial(t1), n, moduli);
    }
}

/// Reusable switch from a designated source secret to the target secret.
pub struct BfvKeySwitcher<'a> {
    product: WorkingKeyProduct<'a>,
}

impl<'a> BfvKeySwitcher<'a> {
    /// Binds the key's level and numerical metadata before allocating reusable scratch.
    /// # Errors
    /// Rejects an unprepared key level or a foreign local generating context.
    /// Foreign numerical mismatches retain their detailed diagnostics.
    pub fn try_new(
        context: &'a BfvContext,
        key: &'a BfvKeySwitchingKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        Self::try_with_working_level(context, key.level(), key)
    }

    /// Temporarily rounds c1 to the key's actual working basis, switches there,
    /// restores its product by D=Q/Q_l, then adds the original external c0.
    /// The returned ciphertext retains `external_level` and its ordinary scale.
    ///
    /// # Correctness
    /// Source/target secrets and actual roots agree across both bases. If A is
    /// the native working-key error and H bounds the source secret's l1 norm,
    /// the added external error is at most D*(A+H/2). Caller-supplied bounds
    /// and complete recoverability are not established by numeric checks.
    /// # Errors
    /// Rejects unavailable/non-prefix levels or incompatible actual key metadata.
    pub fn try_with_working_level(
        context: &'a BfvContext,
        external_level: usize,
        key: &'a BfvKeySwitchingKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        Ok(Self {
            product: WorkingKeyProduct::try_new(context, external_level, &key.key)?,
        })
    }

    /// Writes a native ciphertext under the key's actual target secret.
    ///
    /// # Correctness
    /// Input components are canonical residues using the key's actual source
    /// secret and the bound ordered Q/NTT convention. The complete evaluated
    /// error must satisfy the level codec recovery bound.
    /// # Panics
    /// Rejects recorded context/level conflicts and incomplete storage before
    /// writes. Prepared calls
    /// allocate nothing; arithmetic failure may partially overwrite scratch/output.
    pub fn switch_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BfvCiphertext<A>,
        output: &mut BfvCiphertext<B>,
    ) {
        input.check_binding(self.product.context(), self.product.external_level());
        output.check_binding(self.product.context(), self.product.external_level());
        let len = self.product.poly_len();
        assert_eq!(input.as_ref().len(), 2 * len, "BFV input length mismatch");
        assert_eq!(output.as_ref().len(), 2 * len, "BFV output length mismatch");
        let (c0, c1) = input.as_ref().split_at(len);
        self.product.product_to(c1, None, output.as_mut());
        DcrtPolynomial(&mut output.as_mut()[..len]).add_assign(
            &DcrtPolynomial(c0),
            self.product.context().parameters().poly_length().get(),
            self.product.moduli(),
        );
    }
}

/// Reusable X -> X^k transformation and unscaled switch back to s.
pub struct BfvAutomorphism<'a> {
    product: WorkingKeyProduct<'a>,
    permutation: &'a NttAutomorphismPermutation,
}

impl<'a> BfvAutomorphism<'a> {
    /// Binds the key's level, numerical metadata and permutation before allocating scratch.
    /// # Errors
    /// Rejects an unprepared key level or a foreign local generating context.
    /// Foreign numerical mismatches retain their detailed diagnostics.
    pub fn try_new(
        context: &'a BfvContext,
        key: &'a BfvAutomorphismKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        Self::try_with_working_level(context, key.level(), key)
    }

    /// Prepares ordinary automorphism with temporary working-basis switching.
    /// Only c1 is rounded; its permuted key product is restored to external Q
    /// and added to the original permuted c0. No external level is consumed.
    ///
    /// # Correctness
    /// The actual key encrypts σ(s) under s at its working level. For native
    /// working-key error A and H>=||s||_1, extra error is bounded by D*(A+H/2).
    /// Rounding commutes with this signed coefficient permutation because D is
    /// odd. All other representation/recovery conditions of `apply_to` remain.
    /// # Errors
    /// Rejects unavailable/non-prefix levels or incompatible actual key metadata.
    pub fn try_with_working_level(
        context: &'a BfvContext,
        external_level: usize,
        key: &'a BfvAutomorphismKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        Ok(Self {
            product: WorkingKeyProduct::try_new(context, external_level, &key.key)?,
            permutation: &key.permutation,
        })
    }

    /// Writes σ(input) under the original secret, including the key-switch error.
    ///
    /// # Correctness
    /// Input components are canonical residues using the key's actual secret
    /// and the bound ordered Q/NTT convention.
    /// The complete evaluated error must satisfy the level codec bound. This
    /// operates on the full ciphertext ring; batching row maps choose the
    /// appropriate exponent.
    /// # Panics
    /// Rejects recorded context/level conflicts and incomplete storage before
    /// writes. Prepared calls
    /// allocate nothing; arithmetic failure may partially overwrite scratch/output.
    pub fn apply_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BfvCiphertext<A>,
        output: &mut BfvCiphertext<B>,
    ) {
        input.check_binding(self.product.context(), self.product.external_level());
        output.check_binding(self.product.context(), self.product.external_level());
        let len = self.product.poly_len();
        assert_eq!(input.as_ref().len(), 2 * len, "BFV input length mismatch");
        assert_eq!(output.as_ref().len(), 2 * len, "BFV output length mismatch");
        let (c0, c1) = input.as_ref().split_at(len);
        self.product
            .product_to(c1, Some(self.permutation), output.as_mut());
        self.product
            .add_permuted_to(c0, self.permutation, &mut output.as_mut()[..len]);
    }
}
