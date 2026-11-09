//! Coefficient-domain trace, projection and related-key packing evaluation.

use super::{FourierGlweTraceKey, FourierGlweTraceWorkspace, kernels};
use primus_data::{Data, DataMut};
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_integer::DivRem;
use primus_lattice::{GlweSize, glwe::Glwe, lwe::Lwe};
use primus_modulus::NativeModulus;

/// Reusable storage for packing a fixed number of related-key LWEs.
/// Holds `count` coefficient GLWEs and one trace workspace; evaluation allocates nothing.
pub struct FourierGlwePackingWorkspace<T: TorusFftValue> {
    tree: Vec<T>,
    trace: FourierGlweTraceWorkspace<T>,
}

impl<T: TorusFftValue> FourierGlwePackingWorkspace<T> {
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
            trace: FourierGlweTraceWorkspace::new(size),
        }
    }
}

impl<T: TorusFftValue> FourierGlweTraceKey<T> {
    /// Applies full ordinary trace, targeting `N*M[0]` in the native torus.
    ///
    /// # Correctness
    /// Use the FFT table instance from key generation. Fourier key switching
    /// inherits the precision requirements of
    /// [`key_switch_to`](crate::FourierGlweKeySwitchingKey::key_switch_to).
    ///
    /// # Panics
    /// Panics before writes if ciphertext, FFT or workspace layouts mismatch.
    pub fn apply_to<Table, A, B>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.apply_partial_to(input, 1, output, fft, workspace);
    }

    /// Applies ordinary partial trace, retaining `retained_coefficient_count`
    /// equally spaced message coefficient positions in one N-coefficient GLWE.
    /// For `r=retained_coefficient_count` and `d=N/r`, the target phase is
    /// `d * sum_{j=0}^{r-1} M[j*d] X^(j*d)`. Ring degree and storage stay unchanged;
    /// `r=N` copies the input and `r=1` retains only the constant position.
    ///
    /// Inherits [`Self::apply_to`]'s representation and compatibility requirements.
    /// Panics before writes unless `retained_coefficient_count` is a power-of-two
    /// divisor of N.
    pub fn apply_partial_to<Table, A, B>(
        &self,
        input: &Glwe<A>,
        retained_coefficient_count: usize,
        output: &mut Glwe<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let levels = kernels::check_degree(
            self.glwe_size.poly_length().get(),
            retained_coefficient_count,
        );
        self.check_io(input.as_ref(), output.as_ref(), fft, workspace);
        output.as_mut().copy_from_slice(input.as_ref());
        self.trace_kernel_assign::<_, false>(output.as_mut(), levels, fft, workspace);
    }

    /// Applies full reverse trace, targeting the constant polynomial `M[0]`.
    /// Inherits [`Self::apply_reverse_partial_to`]'s numerical and layout contract.
    pub fn apply_reverse_to<Table, A, B>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.apply_reverse_partial_to(input, 1, output, fft, workspace);
    }

    /// Applies normalized reverse trace, retaining `retained_coefficient_count`
    /// equally spaced message coefficient positions in one N-coefficient GLWE.
    /// For `r=retained_coefficient_count` and `d=N/r`, the target phase is
    /// `sum_{j=0}^{r-1} M[j*d] X^(j*d)`. Ring degree and storage stay unchanged;
    /// `r=N` copies the input and `r=1` retains only the constant position.
    /// The required automorphism keys are used in ascending exponent order.
    ///
    /// Each halving uses unsigned coefficient `floor(x/2)` in the native torus,
    /// including wrapped negative representatives; it does not scale complex FFT data.
    /// Evaluation-key error can remain at non-target coefficients.
    /// Inherits [`Self::apply_to`]'s representation and compatibility requirements.
    /// Panics before writes unless `retained_coefficient_count` is a power-of-two
    /// divisor of N.
    pub fn apply_reverse_partial_to<Table, A, B>(
        &self,
        input: &Glwe<A>,
        retained_coefficient_count: usize,
        output: &mut Glwe<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let levels = kernels::check_degree(
            self.glwe_size.poly_length().get(),
            retained_coefficient_count,
        );
        self.check_io(input.as_ref(), output.as_ref(), fft, workspace);
        output.as_mut().copy_from_slice(input.as_ref());
        self.trace_kernel_assign::<_, true>(output.as_mut(), levels, fft, workspace);
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
    pub fn pack_lwe_to<Table, A, B>(
        &self,
        input: &Lwe<A>,
        output: &mut Glwe<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            input.as_ref().len(),
            self.glwe_size.mask_len() + 1,
            "packing LWE dimension mismatch"
        );
        self.check_output(output.as_ref(), fft, workspace);
        let modulus = NativeModulus::new();
        input.inverse_extract_glwe_to(output, self.glwe_size.poly_length().get(), modulus);
        self.trace_kernel_assign::<_, true>(
            output.as_mut(),
            self.automorphism_count(),
            fft,
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
    pub fn pack_lwes_to<Table, B>(
        &self,
        input: &[T],
        output: &mut Glwe<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlwePackingWorkspace<T>,
    ) where
        Table: FftTable,
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
        self.check_output(output.as_ref(), fft, &workspace.trace);
        let modulus = NativeModulus::new();
        let FourierGlweTraceWorkspace {
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
            |values| {
                for value in values {
                    *value >>= 1u32;
                }
            },
            |index, input, output| {
                self.automorphism_keys[index].apply_kernel_to(
                    Glwe::new(input),
                    Glwe::new(output),
                    fft,
                    automorphism,
                );
            },
        );
    }

    /// Projects coefficient `index` to a constant-message GLWE using a monomial
    /// shift and full reverse trace. Inherits [`Self::apply_reverse_partial_to`]'s contract.
    /// Panics before writes if index >= N or any layout/backend requirement fails.
    pub fn project_coefficient_to<Table, A, B>(
        &self,
        input: &Glwe<A>,
        index: usize,
        output: &mut Glwe<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.project_coefficients_to(input, &[index], output.as_mut(), fft, workspace);
    }

    /// Projects selected coefficients into consecutive GLWE blocks in `indices`
    /// order, including duplicates. Uses one reverse trace per index and reuses scratch.
    /// An empty selection requires empty output. Inherits
    /// [`Self::apply_reverse_partial_to`]'s numerical and representation requirements.
    /// Panics before writes on out-of-range indices or incompatible lengths/backend.
    pub fn project_coefficients_to<Table, A>(
        &self,
        input: &Glwe<A>,
        indices: &[usize],
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweTraceWorkspace<T>,
    ) where
        Table: FftTable,
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
            fft,
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
    pub fn project_prefix_coefficients_to<Table, A>(
        &self,
        input: &Glwe<A>,
        count: usize,
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
    {
        assert!(
            count <= self.glwe_size.poly_length().get(),
            "projection prefix exceeds polynomial length"
        );
        self.project_indices_to(input.as_view(), 0..count, output, fft, workspace);
    }

    // Public callers validate the index range. Check the remaining layouts
    // once, then use the same arithmetic for a slice iterator or a prefix range.
    fn project_indices_to<Table>(
        &self,
        input: Glwe<&[T]>,
        indices: impl ExactSizeIterator<Item = usize>,
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweTraceWorkspace<T>,
    ) where
        Table: FftTable,
    {
        let glwe_len = self.glwe_size.glwe_len();
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
        self.assert_compatible(fft, workspace);
        let modulus = NativeModulus::new();
        kernels::project_to(input, indices, output, self.glwe_size, modulus, |output| {
            self.trace_kernel_assign::<_, true>(output, self.automorphism_count(), fft, workspace);
        });
    }

    /// Expands all N coefficients to constant-message GLWEs in natural index order.
    /// Equivalent to [`Self::expand_partial_coefficients_to`] with `count=N`;
    /// no zero-tail message assumption is needed. Inherits that method's
    /// numerical, representation, layout and panic conditions.
    pub fn expand_coefficients_to<Table, A>(
        &self,
        input: &Glwe<A>,
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
    {
        self.expand_partial_coefficients_to(
            input,
            self.glwe_size.poly_length().get(),
            output,
            fft,
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
    /// The input coefficients are divided by count using unsigned floor division
    /// once before the unscaled tree. Rounding and evaluation error can remain
    /// at every output phase coefficient; their distribution differs from
    /// [`Self::project_coefficients_to`].
    ///
    /// # Panics
    /// Panics before writes unless count is a power of two in `1..=N`, output
    /// contains exactly count GLWE blocks, and input, backend and workspace match the key.
    pub fn expand_partial_coefficients_to<Table, A>(
        &self,
        input: &Glwe<A>,
        count: usize,
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweTraceWorkspace<T>,
    ) where
        Table: FftTable,
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
        self.assert_compatible(fft, workspace);
        if count == 1 {
            output.copy_from_slice(input.as_ref());
            return;
        }

        let log_count = count.trailing_zeros();
        let modulus = NativeModulus::new();
        let FourierGlweTraceWorkspace {
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
                for value in values {
                    *value >>= log_count;
                }
            },
            |index, input, output| {
                self.automorphism_keys[index].apply_kernel_to(
                    Glwe::new(input),
                    Glwe::new(output),
                    fft,
                    automorphism,
                );
            },
        );
    }

    fn check_io<Table>(
        &self,
        input: &[T],
        output: &[T],
        fft: &mut FftEngine<'_, Table>,
        workspace: &FourierGlweTraceWorkspace<T>,
    ) where
        Table: FftTable,
    {
        assert_eq!(
            input.len(),
            self.glwe_size.glwe_len(),
            "trace input layout mismatch"
        );
        self.check_output(output, fft, workspace);
    }

    fn check_output<Table>(
        &self,
        output: &[T],
        fft: &mut FftEngine<'_, Table>,
        workspace: &FourierGlweTraceWorkspace<T>,
    ) where
        Table: FftTable,
    {
        assert_eq!(
            output.len(),
            self.glwe_size.glwe_len(),
            "trace output layout mismatch"
        );
        self.assert_compatible(fft, workspace);
    }

    /// Checks shared backend and immutable workspace layout once per public call.
    fn assert_compatible<Table>(
        &self,
        fft: &FftEngine<'_, Table>,
        workspace: &FourierGlweTraceWorkspace<T>,
    ) where
        Table: FftTable,
    {
        self.automorphism_keys[0].assert_compatible(fft, &workspace.automorphism);
    }

    /// Requires validated ciphertext, key and workspace layouts.
    fn trace_kernel_assign<Table, const REVERSE: bool>(
        &self,
        output: &mut [T],
        levels: usize,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweTraceWorkspace<T>,
    ) where
        Table: FftTable,
    {
        let modulus = NativeModulus::new();
        let FourierGlweTraceWorkspace {
            automorphism_output,
            automorphism,
        } = workspace;
        kernels::trace_assign::<_, _, _, _, REVERSE>(
            output,
            levels,
            automorphism_output.as_mut(),
            modulus,
            |values| {
                for value in values {
                    *value >>= 1u32;
                }
            },
            |index, input, output| {
                self.automorphism_keys[index].apply_kernel_to(
                    Glwe::new(input),
                    Glwe::new(output),
                    fft,
                    automorphism,
                );
            },
        );
    }
}
