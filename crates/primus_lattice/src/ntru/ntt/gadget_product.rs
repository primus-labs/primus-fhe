//! Shared NLev and NGSW decomposition, transform, and accumulation kernels.
//!
//! NLEV and NGSW have different encrypted phases but share this arithmetic and
//! level layout. Wrappers choose the accumulator, clear it once per operation,
//! and convert it after the last product. The fused kernel additionally owns
//! initialization of its separate branch sums.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, NttPolynomialIter};
use primus_reduce::FieldContext;

use crate::workspace::NttNtruExternalProductWorkspaceRefMut;

/// Adds the gadget product of `gadget` and `input` to the existing NTT accumulator.
/// This does not clear the accumulator; the caller must initialize it first.
///
/// # Correctness
///
/// Input contains `N = workspace.poly_length()` canonical coefficients. The
/// gadget has `basis.level_count().get()` complete levels in decomposition
/// order, each of length `N` in the NTT table's evaluation order.
/// Gadget values are canonical. Basis, table, and arithmetic modulus agree,
/// and the table polynomial length equals `N`. The selected accumulator has
/// `N` values and is disjoint from the input and decomposition scratch.
/// These conditions are caller obligations, with selected debug diagnostics.
pub(crate) fn accumulate_ntt_gadget_product<T, M, Table>(
    gadget: &[T],
    input: &[T],
    basis: &ApproxSignedBasis<T>,
    modulus: M,
    ntt: &Table,
    workspace: &mut NttNtruExternalProductWorkspaceRefMut<'_, T>,
) where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    let poly_length = workspace.poly_length();

    debug_assert_eq!(ntt.poly_length().get(), poly_length);
    debug_assert_eq!(ntt.modulus(), modulus.value());
    debug_assert_eq!(basis.modulus(), Some(modulus.value()));
    debug_assert_eq!(input.len(), poly_length);
    debug_assert_eq!(gadget.len(), basis.level_count().get() * poly_length);

    // Adjust this input and initialize its carries once. The transformed sum
    // remains live while decomposition scratch is reused across inputs/levels.
    basis.init_value_carry_slice_to(input, workspace.adjusted_poly, workspace.carries);

    for (decomposer, key_level) in basis
        .decomposer_iter()
        .zip(NttPolynomialIter::new(gadget, poly_length))
    {
        decomposer.decompose_slice_to(
            workspace.adjusted_poly,
            workspace.decomposed_ntt,
            workspace.carries,
        );
        ntt.transform_slice(workspace.decomposed_ntt);
        NttPolynomial(workspace.ntt_accumulator.as_mut()).add_mul_assign(
            &key_level,
            &NttPolynomial(&*workspace.decomposed_ntt),
            modulus,
        );
    }
}

/// Adds branches from shared digits, permuting each nonidentity sum only
/// after its final MAC. Each key stores gamma^-1(K_gamma) and is paired with gamma.
/// The wrapper validates complete layouts and initializes the identity output;
/// this kernel initializes the branch sums, without touching live digits.
#[allow(clippy::too_many_arguments)]
pub(crate) fn accumulate_ntt_gadget_prepermuted_sum<T, M, Table, const K: usize>(
    identity: Option<&[T]>,
    branches: [(&[T], &primus_ntt::NttAutomorphismPermutation); K],
    input: &[T],
    basis: &ApproxSignedBasis<T>,
    modulus: M,
    ntt: &Table,
    scratch: &mut [T],
    workspace: &mut NttNtruExternalProductWorkspaceRefMut<'_, T>,
) where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    let n = workspace.poly_length();
    let (sums, permuted) = scratch.split_at_mut(K * n);
    sums.fill(T::ZERO);
    basis.init_value_carry_slice_to(input, workspace.adjusted_poly, workspace.carries);
    let mut levels = branches.map(|(key, _)| NttPolynomialIter::new(key, n));
    // Keep decomposition/NTT outside the branch loop. The sums cannot be merged
    // before applying their distinct automorphisms, nor may digits be redecomposed.
    let mut identity = identity.map(|rows| NttPolynomialIter::new(rows, n));
    for decomposer in basis.decomposer_iter() {
        decomposer.decompose_slice_to(
            workspace.adjusted_poly,
            workspace.decomposed_ntt,
            workspace.carries,
        );
        ntt.transform_slice(workspace.decomposed_ntt);
        let digit = NttPolynomial(&*workspace.decomposed_ntt);
        if let Some(rows) = identity.as_mut() {
            NttPolynomial(workspace.ntt_accumulator.as_mut()).add_mul_assign(
                &rows.next().expect("validated identity level count"),
                &digit,
                modulus,
            );
        }
        for (level, mut sum) in levels
            .iter_mut()
            .zip(primus_poly::NttPolynomialIterMut::new(sums, n))
        {
            sum.add_mul_assign(
                &level.next().expect("validated gadget level count"),
                &digit,
                modulus,
            );
        }
    }
    for ((_, permutation), sum) in branches.into_iter().zip(NttPolynomialIter::new(sums, n)) {
        permutation.apply_to(sum.as_ref(), permuted);
        modulus.reduce_add_slice_assign(workspace.ntt_accumulator.as_mut(), permuted);
    }
}
