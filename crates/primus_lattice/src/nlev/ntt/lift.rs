//! Fuse the first encrypted rotation with lifting a public polynomial.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

use crate::ntru::Ntru;
use crate::workspace::NttNtruCmuxWorkspace;

use super::NttNlev;

impl<S, T> NttNlev<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Lifts a public polynomial while applying the first encrypted rotation.
    ///
    /// `self` encrypts one; `positive` and optional `negative` encrypt bits
    /// `s⁺` and `s⁻` as NLEV, not NGSW. With `R = X^exponent`, this computes
    /// `input ⊙ (self + (R-1)*positive + (R^-1-1)*negative)`.
    /// Only `input` is approximately decomposed. Monomial factors multiply
    /// gadget rows exactly, so small factors are not lost to decomposition.
    /// A zero exponent still lifts `input` with `self`.
    ///
    /// # Correctness
    /// Inherits [`Self::external_product_to`]'s representation, modulus, table,
    /// basis, input and output contracts. All controls use that same key and
    /// basis, with `workspace.level_count().get()` levels. Bits are mutually
    /// exclusive; omit `negative` for a binary secret. `exponent` is in `0..2N`,
    /// already quantized; its inverse is derived modulo `2N`.
    /// If decomposition reconstructs `input - epsilon`, the ideal phase is
    /// `(input - epsilon) * X^(exponent * (s⁺-s⁻))`, plus control noise.
    /// The input must therefore have sufficient scale for this basis.
    /// Output and scratch are overwritten without allocation or reset.
    ///
    /// # Panics
    /// Panics if output has the wrong polynomial length. For nonzero exponents,
    /// panics if initializer/combined scratch lengths differ or if table/workspace
    /// lengths differ during monomial preparation. Scratch may be partly written.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep controls, public input, arithmetic, and scratch explicit"
    )]
    pub fn lift_monomial_to<M, Table, A, B, C>(
        &self,
        positive: &NttNlev<A>,
        negative: Option<&NttNlev<A>>,
        input: &Polynomial<B>,
        exponent: usize,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruCmuxWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = workspace.poly_length().get();
        debug_assert!(exponent < 2 * poly_length);
        debug_assert_eq!(basis.level_count().get(), workspace.level_count().get());
        debug_assert_eq!(positive.as_ref().len(), self.as_ref().len());
        if exponent == 0 {
            self.external_product_to(
                input,
                output,
                basis,
                modulus,
                ntt,
                &mut workspace.external_product,
            );
            return;
        }

        let mut combined = NttNlev(workspace.combined_control.as_mut_slice());
        combined.as_mut().copy_from_slice(self.as_ref());
        // Sequential use lets monomial preparation borrow the digit buffer.
        let factor = workspace.external_product.as_mut().decomposed_ntt;
        ntt.transform_coeff_one_monomial(exponent, factor);
        for value in factor.iter_mut() {
            *value = modulus.reduce_sub(*value, T::ONE);
        }
        combined.add_mul_ntt_polynomial_assign(positive, &NttPolynomial(&*factor), modulus);
        if let Some(negative) = negative {
            debug_assert_eq!(negative.as_ref().len(), self.as_ref().len());
            // In bit-reversed negacyclic order, evaluation points i and N-1-i
            // are inverses. Reversing NTT(X^e-1) therefore gives NTT(X^-e-1).
            factor.reverse();
            combined.add_mul_ntt_polynomial_assign(negative, &NttPolynomial(&*factor), modulus);
        }
        combined.external_product_to(
            input,
            output,
            basis,
            modulus,
            ntt,
            &mut workspace.external_product,
        );
    }
}
