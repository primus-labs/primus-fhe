//! Coefficient-domain NTRU trace with exact modular normalization.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_factor::{FactorSliceOps, ShoupFactor};
use primus_integer::FheUint;
use primus_lattice::ntru::NtruIterMut;
use primus_modulus::PowOf2Modulus;
use primus_ntt::NttTable;
use primus_reduce::{FieldContext, ReduceNeg};
use primus_shape::PolyLength;
use zeroize::Zeroizing;

use super::kernels;
use crate::{
    NlevParameters, NtruCiphertext, NtruSecretKey, NttNtruAutomorphismKey,
    NttNtruAutomorphismWorkspace, NttNtruGadgetEncryptWorkspace, NttNtruSecretKey,
};

/// Reusable coefficient buffers for NTT-key trace, projection and expansion.
pub struct NttNtruTraceWorkspace<T: FheUint> {
    automorphism_output: NtruCiphertext<Vec<T>>,
    automorphism: NttNtruAutomorphismWorkspace<T>,
}

impl<T: FheUint> NttNtruTraceWorkspace<T> {
    /// Allocates workspace for one polynomial length.
    #[must_use]
    pub fn new(poly_length: PolyLength) -> Self {
        let automorphism = NttNtruAutomorphismWorkspace::new(poly_length);
        Self {
            automorphism_output: NtruCiphertext::zero(poly_length.get()),
            automorphism,
        }
    }
}

/// The `log2(N)` automorphism keys used by trace, projection and expansion.
/// Inputs and outputs stay in coefficient form under the original NTRU secret.
#[derive(Clone)]
pub struct NttNtruTraceKey<T: FheUint> {
    automorphism_keys: Vec<NttNtruAutomorphismKey<T>>,
    inverse_two: T,
    // Entry j normalizes expansion of 2^j coefficients before the tree.
    inverse_expansion_lengths: Vec<ShoupFactor<T>>,
}

impl<T: FheUint> NttNtruTraceKey<T> {
    /// Binary trace keys in descending degree order; projection construction
    /// borrows their ciphertexts before storing inverse-permuted copies.
    pub(crate) fn automorphism_keys(&self) -> &[NttNtruAutomorphismKey<T>] {
        &self.automorphism_keys
    }

    /// Generates keys for degrees `N+1, N/2+1, ..., 3` under one secret.
    /// Encodes the secret once and reuses two local coefficient buffers, erased
    /// on return or unwind. Each degree retains its own key and permutation.
    ///
    /// # Correctness
    /// Inherits [`NttNtruAutomorphismKey::generate`]'s key identity, bounded
    /// signed coefficients and NTT representation requirements.
    ///
    /// # Panics
    /// Inherits that method's resource checks. Also panics before sampling
    /// unless the ciphertext modulus is odd and below `2^(T::BITS-1)`, as
    /// required by the precomputed normalization factors.
    #[must_use]
    pub fn generate<M, Table, R>(
        secret_key: &NtruSecretKey<T>,
        ntt_secret_key: &NttNtruSecretKey<T>,
        parameters: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttNtruGadgetEncryptWorkspace<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let q = parameters.encryption_parameters().cipher_modulus().value();
        assert!(
            q & T::ONE == T::ONE && q < T::ONE << (T::BITS - 1),
            "trace normalization requires an odd modulus below 2^(T::BITS-1)"
        );
        let log_n = parameters.poly_length().log_n();
        let n = parameters.poly_length().get();
        assert_eq!(secret_key.poly_length(), n, "trace secret length mismatch");
        ntt_secret_key.assert_gadget_domain(parameters, ntt, workspace);
        let automorphism_keys = {
            // Every degree permutes the same encoded secret. Keep two independent
            // buffers for the whole batch, and erase them before returning the key.
            let mut encoded = Zeroizing::new(vec![T::ZERO; n]);
            let mut permuted = Zeroizing::new(vec![T::ZERO; n]);
            parameters
                .encryption_parameters()
                .cipher_modulus()
                .encode_signed_slice_to(secret_key.as_slice(), encoded.as_mut_slice());
            (1..=log_n)
                .rev()
                .map(|shift| {
                    NttNtruAutomorphismKey::generate_encoded_kernel(
                        (1usize << shift) + 1,
                        &encoded,
                        &mut permuted,
                        ntt_secret_key,
                        parameters,
                        ntt,
                        rng,
                        workspace,
                    )
                })
                .collect()
        };
        let inverse_two = (q >> 1u32) + T::ONE;
        let mut inverse = T::ONE;
        let mut inverse_expansion_lengths = Vec::with_capacity(log_n as usize + 1);
        for _ in 0..=log_n {
            inverse_expansion_lengths.push(ShoupFactor::new(inverse, q));
            inverse = (inverse >> 1u32) + (inverse & T::ONE) * inverse_two;
        }
        Self {
            automorphism_keys,
            inverse_two,
            inverse_expansion_lengths,
        }
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

    /// Returns the decomposition basis shared by all automorphism keys.
    #[must_use]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        self.automorphism_keys[0].basis()
    }

    /// Applies full ordinary trace, targeting the constant message `N*M[0]`.
    ///
    /// # Correctness
    /// Input contains canonical residues under the original secret and key
    /// modulus. Use the generation NTT representation. Noise, including
    /// key-switch errors and trace amplification, must fit the caller's budget.
    ///
    /// # Panics
    /// Panics before writes if input/output, workspace or NTT lengths, or
    /// arithmetic/table moduli do not match the key.
    pub fn apply_to<M, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.apply_partial_to(input, 1, output, modulus, ntt, workspace);
    }

    /// Retains `r=retained_coefficient_count` equally spaced message positions.
    /// With `d=N/r`, targets `d * sum_j M[j*d] X^(j*d)` in the original ring.
    /// `r=N` copies the input; `r=1` is full trace.
    ///
    /// # Correctness
    /// Inherits [`Self::apply_to`]'s key, representation and noise requirements.
    ///
    /// # Panics
    /// Inherits that method's resource checks. Also panics before writes unless
    /// `retained_coefficient_count` is a power-of-two divisor of N.
    pub fn apply_partial_to<M, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        retained_coefficient_count: usize,
        output: &mut NtruCiphertext<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let levels = kernels::check_count(self.poly_length(), retained_coefficient_count);
        self.check_io(input.as_ref(), output.as_ref(), modulus, ntt, workspace);
        output.as_mut().copy_from_slice(input.as_ref());
        self.trace_kernel_assign::<_, _, false>(output.as_mut(), levels, modulus, ntt, workspace);
    }

    /// Applies full normalized reverse trace, targeting the constant message `M[0]`.
    /// Inherits [`Self::apply_reverse_partial_to`]'s numerical and panic contracts.
    pub fn apply_reverse_to<M, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.apply_reverse_partial_to(input, 1, output, modulus, ntt, workspace);
    }

    /// Applies normalized reverse trace to `r=retained_coefficient_count` positions.
    /// With `d=N/r`, targets `sum_j M[j*d] X^(j*d)` without changing ring degree.
    /// Keys are visited in ascending degree; `r=N` copies input.
    ///
    /// # Correctness
    /// Inherits [`Self::apply_to`]'s key and representation requirements.
    /// Halving multiplies canonical residues by `2^-1 mod q`; it is not rounded
    /// integer division and does not inherit native-torus noise bounds. After
    /// completing the reverse steps, input phase is projected to the retained
    /// positions. Error introduced at degree `2^k+1` is projected to positions
    /// divisible by `N/2^k`, so late key-switch error can occupy non-target
    /// coefficients. These remaining maps are coefficient projections, not
    /// independent real divisions by two. The caller must bound each key-switch
    /// error for the chosen secret, basis and message scale.
    ///
    /// # Panics
    /// Inherits [`Self::apply_partial_to`]'s prewrite checks.
    pub fn apply_reverse_partial_to<M, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        retained_coefficient_count: usize,
        output: &mut NtruCiphertext<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let levels = kernels::check_count(self.poly_length(), retained_coefficient_count);
        self.check_io(input.as_ref(), output.as_ref(), modulus, ntt, workspace);
        output.as_mut().copy_from_slice(input.as_ref());
        self.trace_kernel_assign::<_, _, true>(output.as_mut(), levels, modulus, ntt, workspace);
    }

    /// Projects one coefficient to the constant position using a monomial shift
    /// followed by reverse trace. Inherits [`Self::project_coefficients_to`]'s
    /// numerical and prewrite checks; `index` must be below N.
    pub fn project_coefficient_to<M, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        index: usize,
        output: &mut NtruCiphertext<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.project_coefficients_to(input, &[index], output.as_mut(), modulus, ntt, workspace);
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
    pub fn project_coefficients_to<M, Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        indices: &[usize],
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
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
            modulus,
            ntt,
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
    pub fn project_prefix_coefficients_to<M, Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        count: usize,
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        assert!(
            count <= self.poly_length(),
            "projection prefix exceeds polynomial length"
        );
        self.project_indices_to(input.as_view(), 0..count, output, modulus, ntt, workspace);
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
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit coefficient and decomposition scratch"
    )]
    pub fn project_prefix_coefficients_with_scratch_to<M, Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        count: usize,
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        scratch: &mut [T],
        external_product: &mut crate::NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
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
        self.automorphism_keys[0].assert_external_product_compatible(
            modulus,
            ntt,
            external_product,
        );
        let exponents = PowOf2Modulus::new(2 * n);
        for (index, mut output) in NtruIterMut::new(output, n).enumerate() {
            input.mul_monomial_to(exponents.reduce_neg(index), &mut output, modulus);
            self.reverse_prefix_assign(
                output.as_mut(),
                self.automorphism_count(),
                scratch,
                modulus,
                ntt,
                external_product,
            );
        }
    }

    /// Execute the first `levels` reverse stages (degrees 3, 5, 9, ...).
    /// The caller validates the ring, canonical input, workspace and levels <= log2(N).
    /// Scratch is exactly 2N. Unlike partial trace, this always starts at degree 3;
    /// the omitted terminal stages are supplied by the projection's fused block.
    pub(crate) fn reverse_prefix_assign<M, Table>(
        &self,
        output: &mut [T],
        levels: usize,
        scratch: &mut [T],
        modulus: M,
        ntt: &Table,
        external_product: &mut crate::NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let (automorphism_output, coefficients) = scratch.split_at_mut(self.poly_length());
        let offset = self.automorphism_count() - levels;
        kernels::trace_assign::<_, _, _, _, true>(
            output,
            levels,
            automorphism_output,
            modulus,
            |values| {
                for value in values {
                    *value = (*value >> 1u32) + (*value & T::ONE) * self.inverse_two;
                }
            },
            |index, input, output| {
                self.automorphism_keys[offset + index].apply_with_scratch_kernel_to(
                    NtruCiphertext::new(input),
                    NtruCiphertext::new(output),
                    modulus,
                    ntt,
                    coefficients,
                    external_product,
                )
            },
        );
    }

    // Public callers validate the index range. Check the remaining layouts
    // once, then use the same arithmetic for a slice iterator or a prefix range.
    fn project_indices_to<M, Table>(
        &self,
        input: NtruCiphertext<&[T]>,
        indices: impl ExactSizeIterator<Item = usize>,
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        self.check_batch(
            input.as_ref(),
            indices.len(),
            output,
            modulus,
            ntt,
            workspace,
        );
        let n = self.poly_length();
        let exponents = PowOf2Modulus::new(2 * n);
        for (index, mut output) in indices.zip(NtruIterMut::new(output, n)) {
            input.mul_monomial_to(exponents.reduce_neg(index), &mut output, modulus);
            self.trace_kernel_assign::<_, _, true>(
                output.as_mut(),
                self.automorphism_count(),
                modulus,
                ntt,
                workspace,
            );
        }
    }

    /// Expands every coefficient to a constant-message NTRU in natural order.
    /// Equivalent to [`Self::expand_partial_coefficients_to`] with count=N,
    /// requiring no message zero-tail assumption. Output holds N*N coefficients.
    pub fn expand_coefficients_to<M, Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        self.expand_partial_coefficients_to(
            input,
            self.poly_length(),
            output,
            modulus,
            ntt,
            workspace,
        );
    }

    /// Expands a message supported on its first `count` coefficients to `count`
    /// constant-message NTRUs in natural order, in the same N-coefficient ring.
    /// Uses output as tree storage and count-1 automorphisms without allocation.
    ///
    /// # Correctness
    /// The target message must be zero at every position >= count. Neither the
    /// ciphertext nor its noise needs a zero tail. A general message instead
    /// yields residue-class polynomials `sum_j M[i+j*count] X^(j*count)`.
    /// Inherits [`Self::apply_to`]'s representation requirements. Normalization
    /// multiplies input by `count^-1 mod q` before the unscaled tree. Its modular
    /// error distribution differs from reverse-trace projection and must fit
    /// the caller's budget; non-target output coefficients can contain noise.
    ///
    /// # Panics
    /// Panics before writes unless count is a power-of-two divisor of N,
    /// output has exactly count*N coefficients, and input/resources match the key.
    pub fn expand_partial_coefficients_to<M, Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        count: usize,
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        kernels::check_count(self.poly_length(), count);
        self.check_batch(input.as_ref(), count, output, modulus, ntt, workspace);
        if count == 1 {
            output.copy_from_slice(input.as_ref());
            return;
        }
        let factor = self.inverse_expansion_lengths[count.trailing_zeros() as usize];
        let NttNtruTraceWorkspace {
            automorphism_output,
            automorphism,
        } = workspace;
        kernels::expand_to(
            input.as_ref(),
            output,
            automorphism_output.as_mut(),
            modulus,
            |values| factor.factor_mul_slice_assign(values, modulus.value()),
            |index, input, output| {
                self.automorphism_keys[index].apply_kernel_to(
                    NtruCiphertext::new(input),
                    NtruCiphertext::new(output),
                    modulus,
                    ntt,
                    automorphism,
                )
            },
        );
    }

    fn check_io<M: FieldContext<T>, Table: NttTable<ValueT = T>>(
        &self,
        input: &[T],
        output: &[T],
        modulus: M,
        ntt: &Table,
        workspace: &NttNtruTraceWorkspace<T>,
    ) {
        self.check_batch(input, 1, output, modulus, ntt, workspace);
    }

    fn check_batch<M: FieldContext<T>, Table: NttTable<ValueT = T>>(
        &self,
        input: &[T],
        count: usize,
        output: &[T],
        modulus: M,
        ntt: &Table,
        workspace: &NttNtruTraceWorkspace<T>,
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
        self.automorphism_keys[0].assert_compatible(modulus, ntt, &workspace.automorphism);
    }

    /// Requires checked operands/resources; all keys share one immutable domain.
    fn trace_kernel_assign<M: FieldContext<T>, Table: NttTable<ValueT = T>, const REVERSE: bool>(
        &self,
        output: &mut [T],
        levels: usize,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruTraceWorkspace<T>,
    ) {
        let NttNtruTraceWorkspace {
            automorphism_output,
            automorphism,
        } = workspace;
        kernels::trace_assign::<_, _, _, _, REVERSE>(
            output,
            levels,
            automorphism_output.as_mut(),
            modulus,
            |values| {
                // Canonical inv2 multiplication, without division or a full
                // modular product. Both terms sum to a residue below q.
                for value in values {
                    *value = (*value >> 1u32) + (*value & T::ONE) * self.inverse_two;
                }
            },
            |index, input, output| {
                self.automorphism_keys[index].apply_kernel_to(
                    NtruCiphertext::new(input),
                    NtruCiphertext::new(output),
                    modulus,
                    ntt,
                    automorphism,
                )
            },
        );
    }
}
