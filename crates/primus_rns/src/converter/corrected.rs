use itertools::izip;
use primus_factor::FactorMul;
use primus_integer::{AsInto, FheUint};
use primus_reduce::FieldContext;

use super::BaseConverter;

/// Reusable scratch space for corrected batched RNS base conversion.
///
/// Create this through [`BaseConverter::corrected_conversion_workspace`]. Reusing it
/// for conversions of the same value count avoids allocations in
/// [`BaseConverter::corrected_convert_array`].
pub struct CorrectedConversionWorkspace<T: FheUint> {
    adjusted_residues: Box<[T]>,
    correction_terms: Box<[f64]>,
}

impl<T: FheUint> CorrectedConversionWorkspace<T> {
    fn new(input_moduli_count: usize, value_count: usize) -> Self {
        let adjusted_residues_len = input_moduli_count
            .checked_mul(value_count)
            .expect("corrected conversion workspace length overflow");

        Self {
            adjusted_residues: vec![T::ZERO; adjusted_residues_len].into_boxed_slice(),
            correction_terms: vec![0.0; value_count].into_boxed_slice(),
        }
    }
}

impl<T: FheUint, M: FieldContext<T>> BaseConverter<T, M> {
    /// Allocates reusable scratch space for corrected conversions of one length.
    ///
    /// The returned workspace is sized for this converter's input-modulus count
    /// and can be reused by [`corrected_convert_array`](Self::corrected_convert_array)
    /// when `value_count` is unchanged. A single-modulus input needs no scratch.
    ///
    /// # Panics
    ///
    /// Panics if `input_moduli_count() * value_count` overflows `usize`.
    #[must_use]
    pub fn corrected_conversion_workspace(
        &self,
        value_count: usize,
    ) -> CorrectedConversionWorkspace<T> {
        if self.uses_single_input_kernel() {
            CorrectedConversionWorkspace::new(0, 0)
        } else {
            CorrectedConversionWorkspace::new(self.input_moduli_count(), value_count)
        }
    }

    /// Converts an input-basis array to a single-modulus output basis using
    /// SEAL-style corrected RNS base conversion.
    ///
    /// Unlike fast base conversion, this applies the quotient correction needed
    /// to select the centered lift.
    ///
    /// The output basis must contain exactly one modulus. `input.len()`
    /// must equal `input_moduli_count() * value_count` and uses modulus-major
    /// layout.
    ///
    /// Each input residue vector is interpreted through its centered
    /// representative in `[-Q/2, Q/2)`, where `Q` is the input-base product.
    /// `output.len()` must equal `value_count`; it receives that centered
    /// representative reduced modulo the single output modulus.
    /// For a multi-modulus input, `workspace` must come from
    /// [`corrected_conversion_workspace`](Self::corrected_conversion_workspace) on a
    /// converter with the same input-modulus count and the same `value_count`.
    /// A single-modulus input ignores `workspace`.
    ///
    /// For a multi-modulus input, the correction is estimated with `f64`. The
    /// quotient correction does not guarantee mathematical exactness for every
    /// possible residue vector. When the true correction is within floating-point
    /// error of a half-integer, equivalently when the
    /// centered representative is near the `-Q/2`/`Q/2` boundary, the rounded
    /// correction can be off by one and the result can differ by one multiple of
    /// `Q` modulo the output modulus. Callers requiring mathematical exactness
    /// at that boundary must use a higher-precision method.
    ///
    /// Input values must be canonical residues in their corresponding
    /// input moduli.
    ///
    /// For `value_count == 0`, both data slices must be empty. A general
    /// workspace must still have the matching empty shape; nothing is written.
    ///
    /// # Panics
    ///
    /// Panics if a layout length overflows, the data/workspace shape does not
    /// match, or the output basis does not contain exactly one modulus.
    ///
    /// # Correctness
    ///
    /// A multi-modulus input requires the cross-modulus dot-product range
    /// described by [`Self::fast_convert`].
    pub fn corrected_convert_array(
        &self,
        input: &[T],
        output: &mut [T],
        value_count: usize,
        workspace: &mut CorrectedConversionWorkspace<T>,
    ) {
        let input_moduli_count = self.input_moduli_count();
        let expected_input_len = input_moduli_count
            .checked_mul(value_count)
            .expect("corrected conversion input length overflow");
        assert_eq!(input.len(), expected_input_len);
        assert_eq!(output.len(), value_count);
        assert_eq!(
            self.output_moduli_count(),
            1,
            "output base in corrected_convert_array must be one."
        );

        if self.uses_single_input_kernel() {
            let qi = self.input_base.moduli()[0];
            let qi_value = qi.value();
            let max_nonnegative = (qi_value - T::ONE) / T::TWO;
            let p = self.output_base.moduli()[0];
            let qi_mod_p = p.reduce(qi_value);

            output.iter_mut().zip(input).for_each(|(result, &ai)| {
                let ai_mod_p = p.reduce(ai);
                *result = if ai > max_nonnegative {
                    p.reduce_sub(ai_mod_p, qi_mod_p)
                } else {
                    ai_mod_p
                };
            });
            return;
        }

        assert_eq!(
            workspace.adjusted_residues.len(),
            expected_input_len,
            "corrected conversion workspace has the wrong input shape"
        );
        assert_eq!(
            workspace.correction_terms.len(),
            value_count,
            "corrected conversion workspace has the wrong value count"
        );

        if value_count == 0 {
            return;
        }

        let adjusted_residues = &mut workspace.adjusted_residues;
        let correction_terms = &mut workspace.correction_terms;
        correction_terms.fill(0.0);

        // Calculate a_i * (Q / q_i)^-1 mod q_i and accumulate
        // sum_i(adjusted_residue_i / q_i) for each value.
        izip!(
            input.chunks_exact(value_count),
            self.input_base.inv_punctured_product_mod_modulus(),
            self.input_base.moduli()
        )
        .enumerate()
        .for_each(|(i, (residues_mod_qi, &inv_q_div_qi_mod_qi, &qi))| {
            let qi_val = qi.value();
            let divisor: f64 = qi_val.as_into();
            if inv_q_div_qi_mod_qi.value().is_one() {
                izip!(
                    residues_mod_qi,
                    adjusted_residues
                        .iter_mut()
                        .skip(i)
                        .step_by(input_moduli_count),
                    correction_terms.iter_mut()
                )
                .for_each(|(&ai, adjusted_residue, correction)| {
                    *adjusted_residue = ai;
                    let adjusted_residue: f64 = ai.as_into();
                    *correction += adjusted_residue / divisor;
                });
            } else {
                izip!(
                    residues_mod_qi,
                    adjusted_residues
                        .iter_mut()
                        .skip(i)
                        .step_by(input_moduli_count),
                    correction_terms.iter_mut()
                )
                .for_each(|(&ai, adjusted_residue, correction)| {
                    *adjusted_residue = inv_q_div_qi_mod_qi.factor_mul_modulo(ai, qi_val);
                    let adjusted_residue: f64 = (*adjusted_residue).as_into();
                    *correction += adjusted_residue / divisor;
                });
            }
        });

        let p = self.output_base.moduli()[0];
        let q_mod_p = p.reduce(self.input_base.moduli_product().0);
        let q_div_qi_mod_p = self.iter_base_change_matrix().next().unwrap();

        // Subtract round(sum(u_i/q_i))*Q from the unreduced CRT sum to
        // select its centered lift, using one shared correction per value.
        izip!(
            output,
            adjusted_residues.chunks_exact(input_moduli_count),
            correction_terms.iter(),
        )
        .for_each(|(result, ai_mul_inv_q_div_qi_mod_qi, &correction)| {
            let sum_mod_p = p.reduce_dot_product(ai_mul_inv_q_div_qi_mod_qi, q_div_qi_mod_p);
            let rounded_correction: T = (correction + 0.5).as_into();
            let correction_q_mod_p = p.reduce_mul(rounded_correction, q_mod_p);
            *result = p.reduce_sub(sum_mod_p, correction_q_mod_p);
        });
    }
}
