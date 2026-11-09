//! Fused external-product sums and shared-decomposition automorphism products.
//!
//! Ordinary sums decompose each input independently and invert once after the
//! sum. Prepermuted products share digits across branches and remain in NTT
//! form. Each entry point documents its layout checks and scratch ownership.

use core::borrow::Borrow;

use primus_data::Data;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_reduce::FieldContext;

use crate::ntru::{Ntru, NttNtru, accumulate_ntt_gadget_product};
use crate::workspace::NttNtruExternalProductWorkspace;

use super::NttNlev;

impl<S, T> NttNlev<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Computes `output = sum_j polynomials[j] odot gadgets[j]`.
    ///
    /// Accumulates every product in the transform domain, then converts once to
    /// coefficient form. Output is overwritten; an empty sum writes zero. The
    /// workspace is reused without allocation or a caller-side reset.
    ///
    /// # Correctness
    /// Each pair inherits [`Self::external_product_to`]'s representation, basis,
    /// table and workspace contracts. Gadgets and polynomials have equal counts
    /// and matching order; all use the same basis. Inputs may be borrowed objects
    /// or semantic iterators over packed storage. Polynomial items convert to
    /// shared views via `Into`; pass `output.as_mut_view()` for an owned output.
    /// Callers constructing chunk iterators must exclude incomplete trailing objects.
    ///
    /// # Panics
    /// Panics on unequal reported iterator counts or incorrect object lengths.
    /// Counts, output length and gadget-length overflow are checked before writes.
    /// Each pair is checked as consumed; an invalid pair or panicking iterator may
    /// leave output holding a partial NTT-domain sum. It is not a coefficient result.
    /// Reusing the workspace in a valid call needs no reset.
    pub fn external_product_sum_to<'a, M, Table, I, J>(
        gadgets: I,
        polynomials: J,
        mut output: Ntru<&mut [T]>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        I: IntoIterator<Item: Borrow<Self>, IntoIter: ExactSizeIterator>,
        J: IntoIterator<Item: Into<Polynomial<&'a [T]>>, IntoIter: ExactSizeIterator>,
    {
        let gadgets = gadgets.into_iter();
        let polynomials = polynomials.into_iter();
        assert_eq!(
            gadgets.len(),
            polynomials.len(),
            "external-product sum requires one gadget per polynomial"
        );
        let poly_length = workspace.poly_length().get();
        assert_eq!(
            output.as_ref().len(),
            poly_length,
            "external-product output length mismatch"
        );
        if gadgets.len() == 0 {
            output.set_zero();
            return;
        }
        let gadget_len = basis
            .level_count()
            .get()
            .checked_mul(poly_length)
            .expect("external-product gadget length overflow");
        // Share coefficient/NTT storage and invert in place after all terms.
        let mut transformed = NttNtru(output.as_mut());
        let mut workspace = workspace.as_mut_with_accumulator(&mut transformed);
        workspace.ntt_accumulator.set_zero();
        for (gadget, polynomial) in gadgets.zip(polynomials) {
            let gadget: &Self = gadget.borrow();
            let polynomial = polynomial.into();
            assert_eq!(
                polynomial.as_ref().len(),
                poly_length,
                "external-product polynomial length mismatch"
            );
            assert_eq!(
                gadget.as_ref().len(),
                gadget_len,
                "external-product gadget length mismatch"
            );
            accumulate_ntt_gadget_product(
                gadget.as_ref(),
                polynomial.as_ref(),
                basis,
                modulus,
                ntt,
                &mut workspace,
            );
        }
        ntt.inverse_transform_slice(workspace.ntt_accumulator.as_mut());
    }
}

impl<T: FheUint> NttNlev<&[T]> {
    /// Writes a sum of prepermuted gadget products in NTT form, sharing one
    /// decomposition and one forward transform per digit across all branches.
    ///
    /// # Correctness
    /// Inherits [`Self::external_product_ntt_to`]'s canonical residue, representation
    /// and workspace requirements. For each `(key, gamma)`, key rows must store
    /// `gamma^-1(K_gamma)` in the table's NTT order, using the supplied basis.
    /// These views describe row layout, not ordinary NLev encryption semantics.
    /// The result is `sum_gamma gamma(sum_j d_j*key_j)`, plus `sum_j d_j*identity_j`
    /// when `identity` is present. With `None`, no identity term is added: callers
    /// implementing trace add the original coefficient ciphertext themselves.
    /// The caller binds key messages/secrets and matching forward permutations;
    /// length checks cannot establish these identities. This operation does not
    /// apply modular scaling or redecompose permuted digits (which may reach +B/2).
    /// Overwrites canonical output and initializes scratch without allocation.
    ///
    /// # Panics
    /// Checks exact lengths and modulus/table/permutation dimensions before writes.
    /// Scratch has exactly `(K+1)*N` elements: K branch sums and one permutation
    /// buffer. Scratch and output may contain arbitrary initial values.
    #[allow(clippy::too_many_arguments)]
    pub fn external_product_prepermuted_sum_ntt_to<M, Table, const K: usize>(
        identity: Option<Self>,
        branches: [(NttNlev<&[T]>, &primus_ntt::NttAutomorphismPermutation); K],
        input: Ntru<&[T]>,
        mut output: NttNtru<&mut [T]>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        scratch: &mut [T],
        workspace: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let n = workspace.poly_length().get();
        let len = n * basis.level_count().get();
        if let Some(key) = &identity {
            assert_eq!(key.as_ref().len(), len, "identity gadget length mismatch");
        }
        for (key, permutation) in &branches {
            assert_eq!(key.as_ref().len(), len, "branch gadget length mismatch");
            assert_eq!(
                permutation.poly_length().get(),
                n,
                "branch permutation length mismatch"
            );
        }
        assert_eq!(
            input.as_ref().len(),
            n,
            "external-product input length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            n,
            "external-product output length mismatch"
        );
        assert_eq!(
            scratch.len(),
            K.checked_add(1)
                .and_then(|count| count.checked_mul(n))
                .expect("external-product scratch length overflow"),
            "external-product scratch length mismatch"
        );
        assert_eq!(
            ntt.poly_length().get(),
            n,
            "external-product table length mismatch"
        );
        assert_eq!(
            ntt.modulus(),
            modulus.value(),
            "external-product table modulus mismatch"
        );
        assert_eq!(
            basis.modulus(),
            Some(modulus.value()),
            "external-product basis modulus mismatch"
        );
        let mut workspace = workspace.as_mut_with_accumulator(&mut output);
        workspace.ntt_accumulator.set_zero();
        crate::ntru::accumulate_ntt_gadget_prepermuted_sum(
            identity.map(|key| key.0),
            branches.map(|(key, permutation)| (key.0, permutation)),
            input.as_ref(),
            basis,
            modulus,
            ntt,
            scratch,
            &mut workspace,
        );
    }
}
