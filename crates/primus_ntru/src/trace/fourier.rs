//! Coefficient-domain native-torus trace with integer representative halving.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_lattice::ntru::NtruIterMut;
use primus_modulus::{NativeModulus, PowOf2Modulus};
use primus_reduce::{EncodeSigned, ReduceNeg};
use primus_shape::PolyLength;
use zeroize::Zeroizing;

use super::kernels;
use crate::{
    FourierNtruAutomorphismKey, FourierNtruAutomorphismWorkspace,
    FourierNtruGadgetEncryptWorkspace, FourierNtruSecretKey, NlevParameters, NtruCiphertext,
    NtruSecretKey,
};

/// Reusable coefficient buffers for Fourier-key trace, projection and expansion.
pub struct FourierNtruTraceWorkspace<T: TorusFftValue> {
    automorphism_output: NtruCiphertext<Vec<T>>,
    automorphism: FourierNtruAutomorphismWorkspace<T>,
}

impl<T: TorusFftValue> FourierNtruTraceWorkspace<T> {
    /// Allocates workspace for one polynomial length.
    #[must_use]
    pub fn new(poly_length: PolyLength) -> Self {
        let automorphism = FourierNtruAutomorphismWorkspace::new(poly_length);
        Self {
            automorphism_output: NtruCiphertext::zero(poly_length.get()),
            automorphism,
        }
    }
}

/// The `log2(N)` automorphism keys used by native-torus trace and expansion.
/// Inputs and outputs stay in coefficient form under the original secret;
/// evaluation keys remain bound to the generating FFT table instance.
#[derive(Clone)]
pub struct FourierNtruTraceKey<T: TorusFftValue> {
    automorphism_keys: Vec<FourierNtruAutomorphismKey<T>>,
}

impl<T: TorusFftValue> FourierNtruTraceKey<T> {
    /// Generates keys for degrees `N+1, N/2+1, ..., 3` under one secret.
    /// Encodes the secret once and reuses two local coefficient buffers, erased
    /// on return or unwind. Each degree retains its own key and permutation.
    ///
    /// # Correctness
    /// Inherits [`FourierNtruAutomorphismKey::generate`]'s key identity and
    /// FFT table instance and precision requirements.
    ///
    /// # Panics
    /// Inherits that method's key, parameter, table and workspace checks.
    #[must_use]
    pub fn generate<Table, R>(
        secret_key: &NtruSecretKey<T>,
        fourier_secret_key: &FourierNtruSecretKey,
        parameters: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruGadgetEncryptWorkspace<T>,
    ) -> Self
    where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        let log_n = parameters.poly_length().log_n();
        let n = parameters.poly_length().get();
        assert_eq!(secret_key.poly_length(), n, "trace secret length mismatch");
        fourier_secret_key.assert_gadget_domain(parameters, fft, workspace);
        let automorphism_keys = {
            // Every degree permutes the same encoded secret. Keep two independent
            // buffers for the whole batch, and erase them before returning the key.
            let mut encoded = Zeroizing::new(vec![T::ZERO; n]);
            let mut permuted = Zeroizing::new(vec![T::ZERO; n]);
            NativeModulus::new()
                .encode_signed_slice_to(secret_key.as_slice(), encoded.as_mut_slice());
            (1..=log_n)
                .rev()
                .map(|shift| {
                    FourierNtruAutomorphismKey::generate_encoded_kernel(
                        (1usize << shift) + 1,
                        &encoded,
                        &mut permuted,
                        fourier_secret_key,
                        parameters,
                        fft,
                        rng,
                        workspace,
                    )
                })
                .collect()
        };
        Self { automorphism_keys }
    }

    /// Returns the unchanged ring polynomial length N.
    #[must_use]
    pub fn poly_length(&self) -> usize {
        self.automorphism_keys[0].poly_length()
    }

    /// Returns the number of available automorphism keys, log2(N).
    #[must_use]
    pub fn automorphism_count(&self) -> usize {
        self.automorphism_keys.len()
    }

    /// Returns the native-torus basis shared by all automorphism keys.
    #[must_use]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        self.automorphism_keys[0].basis()
    }

    /// Applies full ordinary trace, targeting the constant message `N*M[0]`.
    ///
    /// # Correctness
    /// Input uses the original secret and key's native integer width. Reuse the
    /// exact FFT table instance used during generation. Noise, including trace
    /// amplification, key-switch and FFT errors, must fit the caller's budget.
    ///
    /// # Panics
    /// Panics before writes if input/output, FFT or workspace lengths do not match the key.
    pub fn apply_to<Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.apply_partial_to(input, 1, output, fft, workspace);
    }

    /// Retains `r=retained_coefficient_count` equally spaced message positions.
    /// With `d=N/r`, targets `d * sum_j M[j*d] X^(j*d)` in the original ring.
    /// `r=N` copies input; `r=1` is full trace.
    ///
    /// # Correctness
    /// Inherits [`Self::apply_to`]'s key, representation and noise requirements.
    ///
    /// # Panics
    /// Inherits that method's resource checks. Also panics before writes unless
    /// `retained_coefficient_count` is a power-of-two divisor of N.
    pub fn apply_partial_to<Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        retained_coefficient_count: usize,
        output: &mut NtruCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let levels = kernels::check_count(self.poly_length(), retained_coefficient_count);
        self.check_batch(input.as_ref(), 1, output.as_ref(), fft, workspace);
        output.as_mut().copy_from_slice(input.as_ref());
        self.trace_kernel_assign::<_, false>(output.as_mut(), levels, fft, workspace);
    }

    /// Applies full normalized reverse trace, targeting the constant message `M[0]`.
    /// Inherits [`Self::apply_reverse_partial_to`]'s numerical and panic contracts.
    pub fn apply_reverse_to<Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.apply_reverse_partial_to(input, 1, output, fft, workspace);
    }

    /// Applies normalized reverse trace to `r=retained_coefficient_count` positions.
    /// With `d=N/r`, targets `sum_j M[j*d] X^(j*d)` without changing ring degree.
    /// Keys are visited in ascending degree; `r=N` copies input.
    ///
    /// # Correctness
    /// Inherits [`Self::apply_to`]'s key and representation requirements.
    /// Each halving uses unsigned coefficient `floor(c/2)`, including wrapped
    /// negative representatives, before automorphism. It never divides complex
    /// Fourier values by two. The coefficient rounding error enters the phase
    /// multiplied by the NTRU secret f; bound it using that secret's coefficient
    /// norm, together with subsequent trace maps, FFT and key-switch errors.
    /// Non-target coefficients can retain residual noise. GLWE noise bounds
    /// cannot be reused without accounting for this multiplication by f.
    /// More precisely, let `Pi_r` retain positions divisible by `N/r`. At
    /// degree `2^k+1`, let `p_k` be the current ciphertext's coefficient parity
    /// and `e_k` the automorphism phase error after halving. The final phase is
    /// `Pi_r(input_phase) - sum_k Pi_(2^(k-1))(f*p_k) + sum_k Pi_(2^k)(e_k)`
    /// modulo the native modulus. Half-modulus lift terms cancel; the parity
    /// terms need not be independent or unbiased.
    ///
    /// # Panics
    /// Inherits [`Self::apply_partial_to`]'s prewrite checks.
    pub fn apply_reverse_partial_to<Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        retained_coefficient_count: usize,
        output: &mut NtruCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let levels = kernels::check_count(self.poly_length(), retained_coefficient_count);
        self.check_batch(input.as_ref(), 1, output.as_ref(), fft, workspace);
        output.as_mut().copy_from_slice(input.as_ref());
        self.trace_kernel_assign::<_, true>(output.as_mut(), levels, fft, workspace);
    }

    /// Projects one coefficient to the constant position using a monomial shift
    /// followed by reverse trace. Inherits [`Self::project_coefficients_to`]'s
    /// numerical and prewrite checks; `index` must be below N.
    pub fn project_coefficient_to<Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        index: usize,
        output: &mut NtruCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.project_coefficients_to(input, &[index], output.as_mut(), fft, workspace);
    }

    /// Projects selected coefficients into consecutive NTRU blocks in `indices`
    /// order, including duplicates. Performs one reverse trace per index.
    ///
    /// # Correctness
    /// Inherits [`Self::apply_reverse_partial_to`]'s numerical and representation
    /// requirements. Each block targets a constant; noise can remain in its tail.
    ///
    /// # Panics
    /// Panics before writes if any index is outside `[0,N)`, output does not
    /// contain exactly `indices.len()*N` coefficients, or input/resources do not
    /// match the key. Empty indices require empty output, but still validate resources.
    pub fn project_coefficients_to<Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        indices: &[usize],
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
    {
        assert!(
            indices.iter().all(|&index| index < self.poly_length()),
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

    /// Projects coefficients `0..count` into consecutive constant-message NTRUs.
    /// Accepts any `count` in `0..=N`; no zero message tail is required.
    /// Uses one full reverse trace per coefficient, with the same rounding and
    /// error behavior as [`Self::project_coefficients_to`], and allocates nothing.
    /// Inherits that method's numerical and representation requirements.
    ///
    /// # Panics
    /// Panics before writes if `count > N`, output does not contain exactly
    /// `count * N` coefficients, or input/backend/workspace layouts differ
    /// from the key. Zero count requires empty output and still validates resources.
    pub fn project_prefix_coefficients_to<Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        count: usize,
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
    {
        assert!(
            count <= self.poly_length(),
            "projection prefix exceeds polynomial length"
        );
        self.project_indices_to(input.as_view(), 0..count, output, fft, workspace);
    }

    /// Projects `0..count` with caller-owned coefficient and external-product scratch.
    /// Reuses exactly `2*N` coefficients: an automorphism result and a permutation buffer.
    /// All scratch is overwritten before use; neither a reset nor a transform-input buffer is needed.
    /// This supports serial BR/trace/key-switch pipelines sharing one decomposition workspace.
    ///
    /// # Correctness
    /// Inherits [`Self::project_prefix_coefficients_to`]'s key, representation and noise requirements.
    ///
    /// # Panics
    /// Checks count, input/output, exact scratch length and backend resources before output writes.
    pub fn project_prefix_coefficients_with_scratch_to<Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        count: usize,
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        scratch: &mut [T],
        external_product: &mut crate::FourierNtruExternalProductWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
    {
        let n = self.poly_length();
        assert!(count <= n, "projection prefix exceeds polynomial length");
        assert_eq!(input.as_ref().len(), n, "trace input length mismatch");
        assert_eq!(
            output.len(),
            count.checked_mul(n).expect("trace output length overflow"),
            "trace output length mismatch"
        );
        assert_eq!(
            scratch.len(),
            2 * n,
            "trace coefficient scratch length mismatch"
        );
        self.automorphism_keys[0].assert_external_product_compatible(fft, external_product);
        self.project_prefix_with_scratch_kernel_to(
            input.as_view(),
            output,
            fft,
            scratch,
            external_product,
        );
    }

    /// The public boundary validated N input coefficients, complete output blocks,
    /// exactly 2N scratch coefficients and matching backend resources. Reuse the two
    /// scratch halves serially across the projections; each is overwritten before use.
    fn project_prefix_with_scratch_kernel_to<Table: FftTable>(
        &self,
        input: NtruCiphertext<&[T]>,
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        scratch: &mut [T],
        external_product: &mut crate::FourierNtruExternalProductWorkspace<T>,
    ) {
        let n = self.poly_length();
        let (automorphism_output, coefficients) = scratch.split_at_mut(n);
        let exponents = PowOf2Modulus::new(2 * n);
        for (index, mut output) in NtruIterMut::new(output, n).enumerate() {
            input.mul_monomial_to(
                exponents.reduce_neg(index),
                &mut output,
                NativeModulus::new(),
            );
            kernels::trace_assign::<_, _, _, _, true>(
                output.as_mut(),
                self.automorphism_count(),
                automorphism_output,
                NativeModulus::new(),
                |values| {
                    for value in values {
                        *value >>= 1u32;
                    }
                },
                |index, input, output| {
                    self.automorphism_keys[index].apply_with_scratch_kernel_to(
                        NtruCiphertext::new(input),
                        NtruCiphertext::new(output),
                        fft,
                        coefficients,
                        external_product,
                    )
                },
            );
        }
    }

    // Public callers validate the index range. Check the remaining layouts
    // once, then use the same arithmetic for a slice iterator or a prefix range.
    fn project_indices_to<Table>(
        &self,
        input: NtruCiphertext<&[T]>,
        indices: impl ExactSizeIterator<Item = usize>,
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruTraceWorkspace<T>,
    ) where
        Table: FftTable,
    {
        self.check_batch(input.as_ref(), indices.len(), output, fft, workspace);
        let n = self.poly_length();
        let modulus = NativeModulus::new();
        let exponents = PowOf2Modulus::new(2 * n);
        for (index, mut output) in indices.zip(NtruIterMut::new(output, n)) {
            input.mul_monomial_to(exponents.reduce_neg(index), &mut output, modulus);
            self.trace_kernel_assign::<_, true>(
                output.as_mut(),
                self.automorphism_count(),
                fft,
                workspace,
            );
        }
    }

    /// Expands every coefficient to a constant-message NTRU in natural order.
    /// Equivalent to [`Self::expand_partial_coefficients_to`] with count=N,
    /// requiring no message zero-tail assumption. Output holds N*N coefficients.
    pub fn expand_coefficients_to<Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
    {
        self.expand_partial_coefficients_to(input, self.poly_length(), output, fft, workspace);
    }

    /// Expands a message supported on its first `count` coefficients to `count`
    /// constant-message NTRUs in natural order, in the same N-coefficient ring.
    /// Uses output as tree storage and count-1 automorphisms without allocation.
    ///
    /// # Correctness
    /// The target message must be zero at every position >= count. Neither the
    /// ciphertext nor its noise needs a zero tail. A general message instead
    /// yields residue-class polynomials `sum_j M[i+j*count] X^(j*count)`.
    /// Inherits [`Self::apply_to`]'s representation requirements. Input is
    /// normalized once by unsigned integer division by count before the unscaled
    /// tree; rounding errors enter phase multiplied by f. This differs from
    /// reverse-trace projection and requires its own precision/noise budget.
    /// Non-target coefficients can contain noise.
    ///
    /// # Panics
    /// Panics before writes unless count is a power-of-two divisor of N,
    /// output has exactly count*N coefficients, and input/resources match the key.
    pub fn expand_partial_coefficients_to<Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        count: usize,
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruTraceWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
    {
        kernels::check_count(self.poly_length(), count);
        self.check_batch(input.as_ref(), count, output, fft, workspace);
        if count == 1 {
            output.copy_from_slice(input.as_ref());
            return;
        }
        let log_count = count.trailing_zeros();
        let FourierNtruTraceWorkspace {
            automorphism_output,
            automorphism,
        } = workspace;
        kernels::expand_to(
            input.as_ref(),
            output,
            automorphism_output.as_mut(),
            NativeModulus::new(),
            |values| {
                for value in values {
                    *value >>= log_count;
                }
            },
            |index, input, output| {
                self.automorphism_keys[index].apply_kernel_to(
                    NtruCiphertext::new(input),
                    NtruCiphertext::new(output),
                    fft,
                    automorphism,
                )
            },
        );
    }

    fn check_batch<Table: FftTable>(
        &self,
        input: &[T],
        count: usize,
        output: &[T],
        fft: &FftEngine<'_, Table>,
        workspace: &FourierNtruTraceWorkspace<T>,
    ) {
        assert_eq!(
            input.len(),
            self.poly_length(),
            "trace input length mismatch"
        );
        assert_eq!(
            output.len(),
            count
                .checked_mul(self.poly_length())
                .expect("trace output length overflow"),
            "trace output length mismatch"
        );
        self.automorphism_keys[0].assert_compatible(fft, &workspace.automorphism);
    }

    /// Requires checked operands/resources; all keys share one immutable domain.
    fn trace_kernel_assign<Table: FftTable, const REVERSE: bool>(
        &self,
        output: &mut [T],
        levels: usize,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruTraceWorkspace<T>,
    ) {
        let FourierNtruTraceWorkspace {
            automorphism_output,
            automorphism,
        } = workspace;
        kernels::trace_assign::<_, _, _, _, REVERSE>(
            output,
            levels,
            automorphism_output.as_mut(),
            NativeModulus::new(),
            |values| {
                for value in values {
                    *value >>= 1u32;
                }
            },
            |index, input, output| {
                self.automorphism_keys[index].apply_kernel_to(
                    NtruCiphertext::new(input),
                    NtruCiphertext::new(output),
                    fft,
                    automorphism,
                )
            },
        );
    }
}
