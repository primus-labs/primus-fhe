use itertools::{Either, izip};
use primus_factor::FactorMul;
use primus_integer::FheUint;
use primus_reduce::FieldContext;

use super::BaseConverter;
use crate::Residues;

/// One prepared destination-modulus kernel for batched fast conversion.
///
/// General conversion borrows value-major adjusted residues prepared
/// once for the entire input batch. Each limb then differs only in its
/// destination modulus and base-change matrix row.
pub(crate) enum FastConversionLimb<'a, T, M> {
    SingleInput {
        input: &'a [T],
        modulus: &'a M,
    },
    General {
        adjusted_residues: &'a [T],
        input_moduli_count: usize,
        base_change_matrix_row: &'a [T],
        modulus: &'a M,
    },
}

impl<T: FheUint, M: FieldContext<T>> FastConversionLimb<'_, T, M> {
    /// Writes this destination-modulus value block in value order.
    ///
    /// # Correctness
    ///
    /// A general limb requires the cross-modulus dot-product range described
    /// by [`BaseConverter::fast_convert`]. The output must have one entry per
    /// prepared input value. Array conversion and full ModUp obtain it by
    /// slicing validated output; streaming ModUp checks its reusable limb once.
    #[inline]
    pub(crate) fn write_to(self, output: &mut [T]) {
        match self {
            Self::SingleInput { input, modulus } => {
                debug_assert_eq!(output.len(), input.len());
                output
                    .iter_mut()
                    .zip(input)
                    .for_each(|(result, &ai)| *result = modulus.reduce(ai));
            }
            Self::General {
                adjusted_residues,
                input_moduli_count,
                base_change_matrix_row,
                modulus,
            } => {
                debug_assert_eq!(base_change_matrix_row.len(), input_moduli_count);
                let adjusted_residues = adjusted_residues.chunks_exact(input_moduli_count);
                debug_assert_eq!(output.len(), adjusted_residues.len());
                // Copy the small arithmetic context before the value loop;
                // it no longer needs to borrow through the shared base table.
                let modulus = *modulus;
                output
                    .iter_mut()
                    .zip(adjusted_residues)
                    .for_each(|(result, adjusted_residues)| {
                        *result =
                            modulus.reduce_dot_product(adjusted_residues, base_change_matrix_row);
                    });
            }
        }
    }
}

impl<T: FheUint, M: FieldContext<T>> BaseConverter<T, M> {
    /// Returns the minimum scratch length required by
    /// [`fast_convert`](Self::fast_convert).
    #[must_use]
    #[inline]
    pub fn fast_convert_scratch_len(&self) -> usize {
        if self.uses_single_input_kernel() {
            0
        } else {
            self.input_moduli_count()
        }
    }

    /// Returns the minimum scratch length required by the batched
    /// fast-conversion APIs.
    ///
    /// # Panics
    ///
    /// Panics if the required length overflows `usize`.
    #[must_use]
    #[inline]
    pub fn fast_convert_array_scratch_len(&self, value_count: usize) -> usize {
        self.fast_convert_scratch_len()
            .checked_mul(value_count)
            .expect("fast conversion scratch length overflow")
    }

    /// Converts one residue vector from the input basis to the output basis.
    ///
    /// With multiple input moduli, this performs the approximate CRT lift
    /// described in [`BaseConverter`]: the output represents `x + kQ` for some
    /// integer `k`, rather than necessarily the canonical lift `x`. The caller
    /// must use it in a construction that cancels or otherwise accepts the
    /// multiple-of-`Q` term. With one input modulus, conversion is an exact
    /// direct reduction.
    ///
    /// `input.len()` must equal `input_moduli_count()`. Element `i` must
    /// be canonical for the input basis's `i`th modulus.
    ///
    /// `output.len()` must equal `output_moduli_count()`. Element `j`
    /// receives the converted residue for the output basis's `j`th modulus.
    ///
    /// `scratch.len()` must be at least
    /// [`fast_convert_scratch_len`](Self::fast_convert_scratch_len). The
    /// general conversion kernel overwrites only the required prefix with the
    /// adjusted input residues. A single-modulus input basis ignores scratch.
    ///
    /// # Panics
    ///
    /// Panics if the input/output counts are wrong or scratch is too short.
    ///
    /// # Correctness
    ///
    /// With multiple input moduli, each destination `p_j` must support dot
    /// products of adjusted source residues `u_i < q_i` and matrix entries
    /// below `p_j`, even when `u_i >= p_j`. Runtime and derived Barrett explicitly
    /// support both operands below `2^(T::BITS - 2)`. Their modulus construction
    /// already guarantees this range for `q_i` and `p_j`; canonical source
    /// residues and the prepared matrix therefore need no additional checks or
    /// reductions. The scalar accumulator (and each SIMD lane) holds at most
    /// 16 products before reduction. Custom contexts must support the actual
    /// operand ranges; [`FieldContext`] alone does not imply them.
    pub fn fast_convert(
        &self,
        Residues(input): Residues<&[T]>,
        Residues(output): Residues<&mut [T]>,
        scratch: &mut [T],
    ) {
        assert_eq!(input.len(), self.input_moduli_count());
        assert_eq!(output.len(), self.output_moduli_count());

        if self.uses_single_input_kernel() {
            let ai = input[0];
            output
                .iter_mut()
                .zip(self.output_base.moduli())
                .for_each(|(result, modulus)| *result = modulus.reduce(ai));
            return;
        }

        let required_scratch_len = self.fast_convert_scratch_len();
        assert!(scratch.len() >= required_scratch_len);
        let scratch = &mut scratch[..required_scratch_len];

        izip!(
            input,
            self.input_base.inv_punctured_product_mod_modulus(),
            self.input_base.moduli_values().iter().copied(),
            scratch.iter_mut()
        )
        .for_each(|(&ai, &inv_q_div_qi_mod_qi, qi, result)| {
            *result = inv_q_div_qi_mod_qi.factor_mul_modulo(ai, qi);
        });

        let ai_mul_inv_q_div_qi_mod_qi = &*scratch;

        izip!(
            output,
            self.iter_base_change_matrix(),
            self.output_base.moduli()
        )
        .for_each(|(ele, q_div_qi_mod_pj, pj)| {
            *ele = pj.reduce_dot_product(ai_mul_inv_q_div_qi_mod_qi, q_div_qi_mod_pj);
        });
    }

    /// Prepares value-major adjusted residues from a validated modulus-major
    /// input. Each destination limb reuses this transposition and scaling.
    /// Only the required scratch prefix is written; reject undersized scratch
    /// before writing anything. An empty batch borrows an empty prefix.
    #[inline]
    fn prepare_general_fast_convert_array<'a>(
        &self,
        input: &[T],
        value_count: usize,
        scratch: &'a mut [T],
    ) -> &'a [T] {
        let input_moduli_count = self.input_moduli_count();
        debug_assert!(!self.uses_single_input_kernel());
        debug_assert_eq!(input.len(), input_moduli_count * value_count);
        assert!(scratch.len() >= input.len());
        let scratch = &mut scratch[..input.len()];
        if value_count == 0 {
            return scratch;
        }

        izip!(
            input.chunks_exact(value_count),
            self.input_base.inv_punctured_product_mod_modulus(),
            self.input_base.moduli_values(),
        )
        .enumerate()
        .for_each(|(i, (residues_mod_qi, &inverse, &qi))| {
            // Select the identity-factor path once per modulus, before walking
            // values; scalar conversion has only one residue per modulus.
            if inverse.value().is_one() {
                izip!(
                    residues_mod_qi,
                    scratch.iter_mut().skip(i).step_by(input_moduli_count)
                )
                .for_each(|(&ai, result)| *result = ai);
            } else {
                izip!(
                    residues_mod_qi,
                    scratch.iter_mut().skip(i).step_by(input_moduli_count)
                )
                .for_each(|(&ai, result)| *result = inverse.factor_mul_modulo(ai, qi));
            }
        });
        scratch
    }

    /// Prepares one conversion and returns its destination-modulus kernels.
    ///
    /// Adjusted input residues are computed once. The returned iterator then
    /// yields one independently writable modulus block at a time, allowing a
    /// caller to immediately consume that limb before producing the next one.
    /// The caller must establish `input_moduli_count() * value_count` input
    /// elements without overflow. Ordinary conversion and ModDown check their
    /// full slices; ModUp derives this slice from its checked partition range.
    /// General conversion validates scratch before preparing any residues.
    #[inline]
    pub(crate) fn fast_convert_array_limbs<'a>(
        &'a self,
        input: &'a [T],
        value_count: usize,
        scratch: &'a mut [T],
    ) -> impl ExactSizeIterator<Item = FastConversionLimb<'a, T, M>> + 'a {
        let input_moduli_count = self.input_moduli_count();
        debug_assert_eq!(input.len(), input_moduli_count * value_count);

        if self.uses_single_input_kernel() {
            Either::Left(
                self.output_base
                    .moduli()
                    .iter()
                    .map(move |modulus| FastConversionLimb::SingleInput { input, modulus }),
            )
        } else {
            let adjusted_residues =
                self.prepare_general_fast_convert_array(input, value_count, scratch);
            Either::Right(
                self.output_base
                    .moduli()
                    .iter()
                    .zip(self.iter_base_change_matrix())
                    .map(
                        move |(modulus, base_change_matrix_row)| FastConversionLimb::General {
                            adjusted_residues,
                            input_moduli_count,
                            base_change_matrix_row,
                            modulus,
                        },
                    ),
            )
        }
    }

    /// Converts a modulus-major array of residue vectors between bases.
    ///
    /// Each value is converted with the same approximate semantics as
    /// [`Self::fast_convert`]. A multi-modulus input may retain a
    /// multiple-of-`Q` term; a one-modulus input is reduced exactly.
    ///
    /// `input.len()` must equal `input_moduli_count() * value_count` and
    /// uses modulus-major layout: chunk `i` of length `value_count` stores all
    /// values modulo the input basis's `i`th modulus. Every input value
    /// must be a canonical residue for its corresponding input modulus.
    ///
    /// `output.len()` must equal `output_moduli_count() * value_count`
    /// and is written in the same modulus-major layout for the output basis.
    ///
    /// `scratch.len()` must be at least
    /// [`fast_convert_array_scratch_len`](Self::fast_convert_array_scratch_len).
    /// The general conversion kernel overwrites only the required prefix in
    /// value-major layout. A single-modulus input basis ignores scratch.
    ///
    /// Empty input requires empty output; scratch is left unchanged.
    ///
    /// # Panics
    ///
    /// Panics if a layout length overflows, an input/output length is wrong,
    /// or scratch is too short.
    ///
    /// # Correctness
    ///
    /// A multi-modulus input requires the cross-modulus dot-product range
    /// described by [`Self::fast_convert`].
    pub fn fast_convert_array(
        &self,
        input: &[T],
        output: &mut [T],
        value_count: usize,
        scratch: &mut [T],
    ) {
        let expected_out_len = self
            .output_moduli_count()
            .checked_mul(value_count)
            .expect("RNS output length overflow");

        assert_eq!(output.len(), expected_out_len);
        let expected_input_len = self
            .input_moduli_count()
            .checked_mul(value_count)
            .expect("RNS input length overflow");
        assert_eq!(input.len(), expected_input_len);

        self.fast_convert_array_kernel(input, output, value_count, scratch);
    }

    /// Converts full input/output layouts already validated by ordinary
    /// conversion or ModDown, including their length products. Scratch is still
    /// checked when preparing the limbs, before scratch or output writes.
    pub(crate) fn fast_convert_array_kernel(
        &self,
        input: &[T],
        output: &mut [T],
        value_count: usize,
        scratch: &mut [T],
    ) {
        debug_assert_eq!(output.len(), self.output_moduli_count() * value_count);
        if value_count == 0 {
            return;
        }
        output
            .chunks_exact_mut(value_count)
            .zip(self.fast_convert_array_limbs(input, value_count, scratch))
            .for_each(|(output, limb)| limb.write_to(output));
    }

    /// Converts an array and returns output residues as pairs.
    ///
    /// Each value is converted with the same approximate semantics as
    /// [`Self::fast_convert`]. A multi-modulus input may retain a
    /// multiple-of-`Q` term; a one-modulus input is reduced exactly.
    ///
    /// The output basis must contain exactly two moduli. `input.len()`
    /// must equal `input_moduli_count() * value_count` and uses modulus-major
    /// layout. Every input value must be a canonical residue for its
    /// corresponding input modulus.
    ///
    /// `scratch.len()` must be at least
    /// [`fast_convert_array_scratch_len`](Self::fast_convert_array_scratch_len).
    /// A general conversion overwrites and borrows only the required prefix in
    /// value-major layout. A single-input conversion borrows the input
    /// directly and ignores scratch.
    ///
    /// The iterator yields exactly `value_count` items, one `(mod p_0, mod p_1)`
    /// pair per value.
    ///
    /// An empty batch yields no pairs and leaves scratch unchanged.
    ///
    /// # Panics
    ///
    /// Panics if the input length overflows or is wrong, or scratch is too short.
    /// Panics if the output basis does not contain exactly two moduli.
    ///
    /// # Correctness
    ///
    /// A multi-modulus input requires the cross-modulus dot-product range
    /// described by [`Self::fast_convert`].
    pub fn fast_convert_array_to_pair_iter<'a>(
        &'a self,
        input: &'a [T],
        value_count: usize,
        scratch: &'a mut [T],
    ) -> impl ExactSizeIterator<Item = (T, T)> + 'a {
        assert_eq!(
            self.output_moduli_count(),
            2,
            "output base in fast_convert_array_to_pair must contain exactly two moduli"
        );

        let input_moduli_count = self.input_moduli_count();
        assert_eq!(
            input.len(),
            input_moduli_count
                .checked_mul(value_count)
                .expect("RNS input length overflow")
        );
        let p0 = self.output_base.moduli()[0];
        let p1 = self.output_base.moduli()[1];
        if self.uses_single_input_kernel() {
            Either::Left(input.iter().map(move |&ai| (p0.reduce(ai), p1.reduce(ai))))
        } else {
            let scratch = self.prepare_general_fast_convert_array(input, value_count, scratch);
            let mut rows = self.iter_base_change_matrix();
            let q_div_qi_mod_p0 = rows.next().expect("missing first output-base row");
            let q_div_qi_mod_p1 = rows.next().expect("missing second output-base row");

            Either::Right(scratch.chunks_exact(input_moduli_count).map(
                move |ai_mul_inv_q_div_qi_mod_qi| {
                    (
                        p0.reduce_dot_product(ai_mul_inv_q_div_qi_mod_qi, q_div_qi_mod_p0),
                        p1.reduce_dot_product(ai_mul_inv_q_div_qi_mod_qi, q_div_qi_mod_p1),
                    )
                },
            ))
        }
    }
}
