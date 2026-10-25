//! Coefficient-domain trace, projection and related-key packing evaluation.

use primus_data::{Data, DataMut};
use primus_factor::FactorSliceOps;
use primus_integer::{DivRem, FheUint};
use primus_lattice::{
    GlweSize,
    glwe::{Glwe, GlweIterMut},
    lwe::Lwe,
};
use primus_modulus::PowOf2Modulus;
use primus_ntt::NttTable;
use primus_reduce::{FieldContext, ReduceNeg};

use super::{NttGlweTraceKey, NttGlweTraceWorkspace, kernels};

/// Reusable storage for packing a fixed number of related-key LWEs.
/// Holds `count` coefficient GLWEs and one trace workspace; evaluation allocates nothing.
pub struct NttGlwePackingWorkspace<T: FheUint> {
    tree: Vec<T>,
    trace: NttGlweTraceWorkspace<T>,
}

impl<T: FheUint> NttGlwePackingWorkspace<T> {
    /// Allocates workspace for `count` inputs of dimension `k*N`.
    ///
    /// # Panics
    /// Panics if count is not a power of two in `1..=N`, or the allocation length overflows.
    #[must_use]
    pub fn new(size: GlweSize, count: usize) -> Self {
        kernels::check_degree(size.poly_length().get(), count);
        Self {
            tree: vec![
                T::ZERO;
                size.glwe_len()
                    .checked_mul(count)
                    .expect("packing workspace length overflow")
            ],
            trace: NttGlweTraceWorkspace::new(size),
        }
    }
}

impl<T: FheUint> NttGlweTraceKey<T> {
    /// Applies ordinary partial trace, retaining `retained_coefficient_count`
    /// equally spaced message coefficient positions in one N-coefficient GLWE.
    /// For `r=retained_coefficient_count` and `d=N/r`, the target phase is
    /// `d * sum_{j=0}^{r-1} M[j*d] X^(j*d)`. Ring degree and storage stay unchanged;
    /// `r=N` copies the input and `r=1` retains only the constant position.
    ///
    /// Inherits [`Self::apply_to`]'s representation and compatibility requirements.
    /// Panics before writes unless `retained_coefficient_count` is a power-of-two
    /// divisor of N.
    pub fn apply_partial_to<M, Table, A, B>(
        &self,
        input: &Glwe<A>,
        retained_coefficient_count: usize,
        output: &mut Glwe<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let levels = kernels::check_degree(
            self.glwe_size.poly_length().get(),
            retained_coefficient_count,
        );
        self.check_io(input.as_ref(), output.as_ref(), modulus, ntt, workspace);
        output.as_mut().copy_from_slice(input.as_ref());
        self.trace_kernel_assign::<_, _, false>(output.as_mut(), levels, modulus, ntt, workspace);
    }

    /// Applies full reverse trace, targeting the constant polynomial `M[0]`.
    /// Inherits [`Self::apply_reverse_partial_to`]'s numerical and layout contract.
    pub fn apply_reverse_to<M, Table, A, B>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.apply_reverse_partial_to(input, 1, output, modulus, ntt, workspace);
    }

    /// Applies normalized reverse trace, retaining `retained_coefficient_count`
    /// equally spaced message coefficient positions in one N-coefficient GLWE.
    /// For `r=retained_coefficient_count` and `d=N/r`, the target phase is
    /// `sum_{j=0}^{r-1} M[j*d] X^(j*d)`. Ring degree and storage stay unchanged;
    /// `r=N` copies the input and `r=1` retains only the constant position.
    /// The required automorphism keys are used in ascending exponent order.
    ///
    /// Each halving multiplies canonical residues by inv2 modulo q. This is a
    /// field operation, not rounded integer division; the torus RevHomTrace
    /// noise bound does not apply. Callers must budget the resulting modular error.
    /// Evaluation-key error can remain at non-target coefficients.
    /// Inherits [`Self::apply_to`]'s representation and compatibility requirements.
    /// Panics before writes unless `retained_coefficient_count` is a power-of-two
    /// divisor of N.
    pub fn apply_reverse_partial_to<M, Table, A, B>(
        &self,
        input: &Glwe<A>,
        retained_coefficient_count: usize,
        output: &mut Glwe<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let levels = kernels::check_degree(
            self.glwe_size.poly_length().get(),
            retained_coefficient_count,
        );
        self.check_io(input.as_ref(), output.as_ref(), modulus, ntt, workspace);
        output.as_mut().copy_from_slice(input.as_ref());
        self.trace_kernel_assign::<_, _, true>(output.as_mut(), levels, modulus, ntt, workspace);
    }

    /// Converts one related-key LWE into a GLWE targeting the constant message.
    /// Uses inverse sample extraction followed by full reverse trace.
    ///
    /// # Correctness
    /// The LWE key must equal the coefficient flattening of this GLWE key, with
    /// dimension exactly k*N and the same modulus and encoding. Inherits the
    /// numerical requirements of [`Self::apply_reverse_partial_to`].
    ///
    /// # Panics
    /// Panics before writes on incompatible ciphertext, table or workspace layouts.
    pub fn pack_lwe_to<M, Table, A, B>(
        &self,
        input: &Lwe<A>,
        output: &mut Glwe<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            input.as_ref().len(),
            self.glwe_size.mask_len() + 1,
            "packing LWE dimension mismatch"
        );
        self.check_output(output.as_ref(), modulus, ntt, workspace);

        input.inverse_extract_glwe_to(output, self.glwe_size.poly_length().get(), modulus);
        self.trace_kernel_assign::<_, _, true>(
            output.as_mut(),
            self.automorphism_count(),
            modulus,
            ntt,
            workspace,
        );
    }

    /// Packs a contiguous batch of LWEs using the RevHomTrace even/odd tree.
    /// For p inputs, the target is `sum_i m[i] X^(i*N/p)`; p=N gives adjacent slots.
    /// The workspace count must equal p. No allocation occurs during evaluation.
    ///
    /// Inherits [`Self::pack_lwe_to`]'s related-key and numerical requirements.
    /// Panics before writes unless the batch is complete, p is a power of two in
    /// 1..=N, and ciphertext, table and workspace layouts match.
    pub fn pack_lwes_to<M, Table, B>(
        &self,
        input: &[T],
        output: &mut Glwe<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlwePackingWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        B: DataMut<Elem = T>,
    {
        let lwe_len = self.glwe_size.mask_len() + 1;

        let (count, rem) = input.len().div_rem(lwe_len);
        assert_eq!(rem, 0, "packing input contains a partial LWE");

        kernels::check_degree(self.glwe_size.poly_length().get(), count);
        assert_eq!(
            workspace.tree.len(),
            count * self.glwe_size.glwe_len(),
            "packing workspace count mismatch"
        );
        self.check_output(output.as_ref(), modulus, ntt, &workspace.trace);

        let NttGlweTraceWorkspace {
            automorphism_output,
            automorphism,
        } = &mut workspace.trace;
        kernels::pack_to(
            input,
            output.as_mut(),
            &mut workspace.tree,
            automorphism_output.as_mut(),
            self.glwe_size,
            modulus,
            |values| self.halve_assign(values),
            |index, input, output| {
                self.automorphism_keys[index].apply_kernel_to(
                    Glwe::new(input),
                    Glwe::new(output),
                    modulus,
                    ntt,
                    automorphism,
                );
            },
        );
    }

    /// Projects coefficient `index` to a constant-message GLWE using a monomial
    /// shift and full reverse trace. Inherits [`Self::apply_reverse_partial_to`]'s contract.
    /// Panics before writes if index >= N or any layout/backend requirement fails.
    pub fn project_coefficient_to<M, Table, A, B>(
        &self,
        input: &Glwe<A>,
        index: usize,
        output: &mut Glwe<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.project_coefficients_to(input, &[index], output.as_mut(), modulus, ntt, workspace);
    }

    /// Projects selected coefficients into consecutive GLWE blocks in `indices`
    /// order, including duplicates. Uses one reverse trace per index and reuses scratch.
    /// An empty selection requires empty output. Inherits
    /// [`Self::apply_reverse_partial_to`]'s numerical and representation requirements.
    /// Panics before writes on out-of-range indices or incompatible lengths/backend.
    pub fn project_coefficients_to<M, Table, A>(
        &self,
        input: &Glwe<A>,
        indices: &[usize],
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        assert!(
            indices
                .iter()
                .all(|&index| index < self.glwe_size.poly_length().get()),
            "projection index outside polynomial"
        );
        self.project_indices_to(
            input.as_view(),
            indices.iter().copied(),
            output,
            modulus,
            ntt,
            workspace,
        );
    }

    /// Projects coefficients `0..count` into consecutive constant-message GLWEs.
    /// Accepts any `count` in `0..=N`; no zero message tail is required.
    /// Uses one full reverse trace per coefficient, with the same rounding and
    /// error behavior as [`Self::project_coefficients_to`], and allocates nothing.
    /// Inherits that method's numerical and representation requirements.
    ///
    /// # Panics
    /// Panics before writes if `count > N`, output does not contain exactly
    /// `count * size.glwe_len()` coefficients, or input/backend/workspace layouts differ
    /// from the key. Zero count requires empty output and still validates resources.
    pub fn project_prefix_coefficients_to<M, Table, A>(
        &self,
        input: &Glwe<A>,
        count: usize,
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        assert!(
            count <= self.glwe_size.poly_length().get(),
            "projection prefix exceeds polynomial length"
        );
        self.project_indices_to(input.as_view(), 0..count, output, modulus, ntt, workspace);
    }

    // Public callers validate the index range. Check the remaining layouts
    // once, then use the same arithmetic for a slice iterator or a prefix range.
    fn project_indices_to<M, Table>(
        &self,
        input: Glwe<&[T]>,
        indices: impl ExactSizeIterator<Item = usize>,
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let glwe_len = self.glwe_size.glwe_len();
        let poly_length = self.glwe_size.poly_length().get();
        assert_eq!(
            input.as_ref().len(),
            glwe_len,
            "projection input layout mismatch"
        );
        assert_eq!(
            output.len(),
            indices
                .len()
                .checked_mul(glwe_len)
                .expect("projection output length overflow"),
            "projection output length mismatch"
        );
        self.assert_compatible(modulus, ntt, workspace);

        let exponent_modulus = PowOf2Modulus::new(2 * poly_length);
        for (index, mut output) in indices.zip(GlweIterMut::new(output, glwe_len)) {
            input.mul_monomial_to(
                exponent_modulus.reduce_neg(index),
                &mut output,
                poly_length,
                modulus,
            );
            self.trace_kernel_assign::<_, _, true>(
                output.as_mut(),
                self.automorphism_count(),
                modulus,
                ntt,
                workspace,
            );
        }
    }

    /// Expands all N coefficients to constant-message GLWEs in natural index order.
    /// Equivalent to [`Self::expand_partial_coefficients_to`] with `count=N`;
    /// no zero-tail message assumption is needed. Inherits that method's
    /// numerical, representation, layout and panic conditions.
    pub fn expand_coefficients_to<M, Table, A>(
        &self,
        input: &Glwe<A>,
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        self.expand_partial_coefficients_to(
            input,
            self.glwe_size.poly_length().get(),
            output,
            modulus,
            ntt,
            workspace,
        );
    }

    /// Expands a message supported on its first `count` coefficients into
    /// `count` constant-message GLWEs in natural order. Ring degree remains N.
    /// Uses `log2(count)` forward-tree levels and `count-1` automorphisms,
    /// with output itself as tree storage and no evaluation-time allocation.
    /// `count=1` copies the input; `count=N` is full coefficient expansion.
    ///
    /// # Correctness
    /// The target message must have zero coefficients at every index >= count.
    /// This encrypted-message condition is not checked. Ciphertext masks and
    /// bodies need not have zero tails. For a general message, output i retains
    /// `sum_j M[i+j*count] X^(j*count)` instead of a constant.
    /// Input/backend representation requirements are inherited from [`Self::apply_to`].
    /// The input is multiplied by `count^(-1) mod q` once before the unscaled
    /// tree. This field operation does not inherit torus reverse-trace noise
    /// bounds. Evaluation error can remain at every output phase coefficient;
    /// the error distribution differs from [`Self::project_coefficients_to`].
    ///
    /// # Panics
    /// Panics before writes unless count is a power of two in `1..=N`, output
    /// contains exactly count GLWE blocks, and input, backend and workspace match the key.
    pub fn expand_partial_coefficients_to<M, Table, A>(
        &self,
        input: &Glwe<A>,
        count: usize,
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        kernels::check_degree(self.glwe_size.poly_length().get(), count);
        let glwe_len = self.glwe_size.glwe_len();
        assert_eq!(
            input.as_ref().len(),
            glwe_len,
            "expansion input layout mismatch"
        );
        assert_eq!(
            output.len(),
            count
                .checked_mul(glwe_len)
                .expect("expansion output length overflow"),
            "expansion output length mismatch"
        );
        self.assert_compatible(modulus, ntt, workspace);

        if count == 1 {
            output.copy_from_slice(input.as_ref());
            return;
        }

        let log_count = count.trailing_zeros();
        let NttGlweTraceWorkspace {
            automorphism_output,
            automorphism,
        } = workspace;
        kernels::expand_to(
            input.as_ref(),
            output,
            automorphism_output.as_mut(),
            self.glwe_size,
            modulus,
            |values| {
                self.inverse_expansion_lengths[log_count as usize]
                    .factor_mul_slice_assign(values, modulus.value());
            },
            |index, input, output| {
                self.automorphism_keys[index].apply_kernel_to(
                    Glwe::new(input),
                    Glwe::new(output),
                    modulus,
                    ntt,
                    automorphism,
                );
            },
        );
    }

    fn check_io<M: FieldContext<T>, Table: NttTable<ValueT = T>>(
        &self,
        input: &[T],
        output: &[T],
        modulus: M,
        ntt: &Table,
        workspace: &NttGlweTraceWorkspace<T>,
    ) {
        assert_eq!(
            input.len(),
            self.glwe_size.glwe_len(),
            "trace input layout mismatch"
        );
        self.check_output(output, modulus, ntt, workspace);
    }

    fn check_output<M: FieldContext<T>, Table: NttTable<ValueT = T>>(
        &self,
        output: &[T],
        modulus: M,
        ntt: &Table,
        workspace: &NttGlweTraceWorkspace<T>,
    ) {
        assert_eq!(
            output.len(),
            self.glwe_size.glwe_len(),
            "trace output layout mismatch"
        );
        self.assert_compatible(modulus, ntt, workspace);
    }

    /// Checks shared backend and immutable workspace layout once per public call.
    fn assert_compatible<M: FieldContext<T>, Table: NttTable<ValueT = T>>(
        &self,
        modulus: M,
        ntt: &Table,
        workspace: &NttGlweTraceWorkspace<T>,
    ) {
        self.automorphism_keys[0].assert_compatible(modulus, ntt, &workspace.automorphism);
    }

    /// Multiplies canonical residues by inv2 mod q without a full modular product:
    /// x/2 for even x, x/2 + (q+1)/2 for odd x. Both terms sum to a value below q.
    fn halve_assign(&self, values: &mut [T]) {
        for value in values {
            *value = (*value >> 1u32) + (*value & T::ONE) * self.inverse_two;
        }
    }

    /// Requires validated ciphertext, key and workspace layouts.
    fn trace_kernel_assign<M: FieldContext<T>, Table: NttTable<ValueT = T>, const REVERSE: bool>(
        &self,
        output: &mut [T],
        levels: usize,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweTraceWorkspace<T>,
    ) {
        let NttGlweTraceWorkspace {
            automorphism_output,
            automorphism,
        } = workspace;
        kernels::trace_assign::<_, _, _, _, REVERSE>(
            output,
            levels,
            automorphism_output.as_mut(),
            modulus,
            |values| self.halve_assign(values),
            |index, input, output| {
                self.automorphism_keys[index].apply_kernel_to(
                    Glwe::new(input),
                    Glwe::new(output),
                    modulus,
                    ntt,
                    automorphism,
                );
            },
        );
    }
}
