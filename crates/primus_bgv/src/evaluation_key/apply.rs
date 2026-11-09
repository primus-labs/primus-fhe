//! Checked application of each BGV role key.
use primus_data::{Data, DataMut};
use primus_ntt::NttAutomorphismPermutation;
use primus_poly::DcrtPolynomial;

use crate::{BgvCiphertext, BgvContext, advanced::BgvQuadraticCiphertext};

use super::{
    BgvEvaluationKeyError,
    material::{BgvAutomorphismKey, BgvKeySwitchingKey, BgvRelinearizationKey},
    product::NativeGadgetProduct,
};

/// Reusable s²-to-s relinearization at one BGV prefix level.
pub struct BgvRelinearizer<'a> {
    product: NativeGadgetProduct<'a>,
}

impl<'a> BgvRelinearizer<'a> {
    /// Checks the key's exact context and level before allocating reusable scratch.
    /// # Errors
    /// Rejects a foreign context, unprepared key level or different N, p or ordered Q.
    pub fn try_new(
        context: &'a BgvContext,
        key: &'a BgvRelinearizationKey,
    ) -> Result<Self, BgvEvaluationKeyError> {
        Ok(Self {
            product: NativeGadgetProduct::try_new(context, &key.key)?,
        })
    }

    /// Writes `[t0+P0,t1+P1]` for P encrypting t2*s².
    ///
    /// # Correctness
    /// Input components are canonical residues using this actual secret,
    /// ordered level basis and NTT convention.
    /// The output retains the tensor's plaintext correction factor.
    /// Radix residual/key noise or Hybrid key/ModDown corrections contribute
    /// p-scaled error;
    /// the intended output phase must stay in the centered Q interval.
    /// # Panics
    /// Rejects recorded context/level mismatches or incomplete lengths before writes. Calls
    /// allocate nothing; transform/RNS failure may partially overwrite scratch/output.
    pub fn relinearize_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BgvQuadraticCiphertext<A>,
        output: &mut BgvCiphertext<B>,
    ) {
        input.check_binding(self.product.context, self.product.key.level);
        check_output(&self.product, output);
        assert_eq!(
            input.as_ref().len(),
            3 * self.product.poly_len(),
            "BGV quadratic length mismatch"
        );
        self.relinearize_validated_to(input, output);
    }

    // Compound multiplication already checked the output and owns the tensor
    // at this exact level. It must pass the complete 3-component tensor.
    pub(crate) fn relinearize_validated_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BgvQuadraticCiphertext<A>,
        output: &mut BgvCiphertext<B>,
    ) {
        let len = self.product.poly_len();
        let (t0, rest) = input.as_ref().split_at(len);
        let (t1, t2) = rest.split_at(len);
        self.product.product_to(t2, None, output.as_mut());
        let (c0, c1) = output.as_mut().split_at_mut(len);
        let n = self.product.key.n;
        let moduli = self.product.context.base_q(self.product.key.level).moduli();
        DcrtPolynomial(c0).add_assign(&DcrtPolynomial(t0), n, moduli);
        DcrtPolynomial(c1).add_assign(&DcrtPolynomial(t1), n, moduli);
        output.set_correction_factor(input.correction_factor());
    }
}

/// Reusable switch from a designated source secret to the target secret.
pub struct BgvKeySwitcher<'a> {
    product: NativeGadgetProduct<'a>,
}

impl<'a> BgvKeySwitcher<'a> {
    /// Checks the key's exact context and level before allocating reusable scratch.
    /// # Errors
    /// Rejects a foreign context, unprepared key level or different N, p or ordered Q.
    pub fn try_new(
        context: &'a BgvContext,
        key: &'a BgvKeySwitchingKey,
    ) -> Result<Self, BgvEvaluationKeyError> {
        Ok(Self {
            product: NativeGadgetProduct::try_new(context, &key.key)?,
        })
    }

    /// Writes a native ciphertext under the key's actual target secret.
    /// Its plaintext correction factor is preserved.
    ///
    /// # Correctness
    /// Input components are canonical residues using the key's actual source
    /// secret and the bound ordered Q/NTT convention. The output's intended
    /// phase must stay inside centered Q.
    /// # Panics
    /// Rejects recorded context/level mismatches or incomplete lengths before writes. Calls
    /// allocate nothing; arithmetic failure may partially overwrite scratch/output.
    pub fn switch_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BgvCiphertext<A>,
        output: &mut BgvCiphertext<B>,
    ) {
        input.check_binding(self.product.context, self.product.key.level);
        check_output(&self.product, output);
        let len = self.product.poly_len();
        let (c0, c1) = input.c0_c1(len);
        self.product.product_to(c1.as_ref(), None, output.as_mut());
        DcrtPolynomial(&mut output.as_mut()[..len]).add_assign(
            &c0,
            self.product.key.n,
            self.product.context.base_q(self.product.key.level).moduli(),
        );
        output.set_correction_factor(input.correction_factor());
    }
}

/// Reusable X -> X^k transformation and p-preserving switch back to s.
pub struct BgvAutomorphism<'a> {
    product: NativeGadgetProduct<'a>,
    permutation: &'a NttAutomorphismPermutation,
}

impl<'a> BgvAutomorphism<'a> {
    /// Checks the key's exact context, level and permutation before allocating scratch.
    /// # Errors
    /// Rejects a foreign context, unprepared key level or different N, p or ordered Q.
    pub fn try_new(
        context: &'a BgvContext,
        key: &'a BgvAutomorphismKey,
    ) -> Result<Self, BgvEvaluationKeyError> {
        Ok(Self {
            product: NativeGadgetProduct::try_new(context, &key.key)?,
            permutation: &key.permutation,
        })
    }

    /// Writes σ(input) under the original secret, including the key-switch error.
    /// The scalar plaintext correction is unchanged by the permutation.
    ///
    /// # Correctness
    /// Input components are canonical residues using the key's actual secret
    /// and the bound ordered Q/NTT convention.
    /// The output's intended phase must stay in centered Q. This operates on the
    /// full ciphertext ring; batching row maps choose the appropriate exponent.
    /// # Panics
    /// Rejects recorded context/level mismatches or incomplete lengths before writes. Calls
    /// allocate nothing; arithmetic failure may partially overwrite scratch/output.
    pub fn apply_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BgvCiphertext<A>,
        output: &mut BgvCiphertext<B>,
    ) {
        input.check_binding(self.product.context, self.product.key.level);
        check_output(&self.product, output);
        let len = self.product.poly_len();
        let (c0, c1) = input.c0_c1(len);
        self.product
            .product_to(c1.as_ref(), Some(self.permutation), output.as_mut());
        let n = self.product.key.n;
        for (input, scratch) in c0
            .as_ref()
            .chunks_exact(n)
            .zip(self.product.coefficient.chunks_exact_mut(n))
        {
            self.permutation.apply_to(input, scratch);
        }
        DcrtPolynomial(&mut output.as_mut()[..len]).add_assign(
            &DcrtPolynomial(self.product.coefficient.as_slice()),
            n,
            self.product.context.base_q(self.product.key.level).moduli(),
        );
        output.set_correction_factor(input.correction_factor());
    }
}

fn check_output<C: Data<Elem = u64>>(product: &NativeGadgetProduct<'_>, output: &BgvCiphertext<C>) {
    output.check_binding(product.context, product.key.level);
    assert_eq!(
        output.as_ref().len(),
        2 * product.poly_len(),
        "BGV output length mismatch"
    );
}
