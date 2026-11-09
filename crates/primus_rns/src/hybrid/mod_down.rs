use itertools::izip;
use primus_integer::FheUint;
use primus_reduce::FieldContext;

use super::HybridRNS;

impl<T, M> HybridRNS<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Approximately converts a coefficient-domain polynomial from `P` to
    /// `Q` for ModDown.
    ///
    /// `polynomial_mod_p` must contain `p_moduli_count() * poly_length`
    /// elements in modulus-major order. `polynomial_mod_q` must contain
    /// `q_moduli_count() * poly_length` elements. `scratch.len()` must be at
    /// least [`mod_down_scratch_len`](Self::mod_down_scratch_len). A
    /// single-prime `P` ignores scratch.
    /// Only the required scratch prefix is overwritten. Zero length requires
    /// empty input and output and performs no writes.
    ///
    /// # Panics
    ///
    /// Panics if an input, output, or scratch buffer has the wrong length, or
    /// if a derived polynomial length overflows `usize`.
    ///
    /// # Correctness
    ///
    /// Input residues must be canonical for this instance's ordered P basis.
    /// Conversion retains the approximate lift described by
    /// [`crate::BaseConverter::fast_convert`], including its arithmetic requirements.
    pub fn approx_convert_p_to_q_to(
        &self,
        polynomial_mod_p: &[T],
        polynomial_mod_q: &mut [T],
        poly_length: usize,
        scratch: &mut [T],
    ) {
        // The converter owns exactly the P -> Q bases and checks both layouts.
        self.mod_down_converter.fast_convert_array(
            polynomial_mod_p,
            polynomial_mod_q,
            poly_length,
            scratch,
        );
    }

    /// Approximately divides a coefficient-domain `QP` polynomial by `P` and
    /// leaves the result in its `Q` limbs.
    ///
    /// `polynomial_mod_qp` is overwritten in its `Q` limbs, while its `P` limbs
    /// are left unchanged. `correction_mod_q` must hold
    /// `q_moduli_count() * poly_length` elements. `scratch.len()` must be at
    /// least [`mod_down_scratch_len`](Self::mod_down_scratch_len). A
    /// single-prime `P` ignores scratch.
    /// Zero length requires empty data slices and performs no writes.
    ///
    /// # Panics
    ///
    /// Panics if an input, output, or scratch buffer has the wrong length, or
    /// if a derived polynomial length overflows `usize`.
    ///
    /// # Correctness
    ///
    /// Input residues must be canonical in this instance's `Q || P` order.
    /// The P-to-Q conversion requirements of
    /// [`approx_convert_p_to_q_to`](Self::approx_convert_p_to_q_to) apply.
    pub fn approx_mod_down_q_assign(
        &self,
        polynomial_mod_qp: &mut [T],
        poly_length: usize,
        correction_mod_q: &mut [T],
        scratch: &mut [T],
    ) {
        let q_len = self
            .q_moduli_count()
            .checked_mul(poly_length)
            .expect("hybrid Q polynomial length overflow");
        let p_len = self
            .p_moduli_count()
            .checked_mul(poly_length)
            .expect("hybrid P polynomial length overflow");
        let qp_len = q_len
            .checked_add(p_len)
            .expect("hybrid QP polynomial length overflow");
        assert_eq!(polynomial_mod_qp.len(), qp_len);
        assert_eq!(correction_mod_q.len(), q_len);

        let (polynomial_mod_q, polynomial_mod_p) = polynomial_mod_qp.split_at_mut(q_len);
        // Splitting the checked QP layout proves the converter's P input size;
        // its Q output was checked above. Only scratch remains to be checked.
        self.mod_down_converter.fast_convert_array_kernel(
            polynomial_mod_p,
            correction_mod_q,
            poly_length,
            scratch,
        );
        self.mod_down_from_correction_q_kernel(polynomial_mod_q, correction_mod_q, poly_length);
    }

    /// Applies a prepared ModDown correction to a coefficient-domain `Q`
    /// polynomial in place.
    ///
    /// Both slices must contain `q_moduli_count() * poly_length` elements in
    /// modulus-major order. For each `q_i`, this computes
    /// `(polynomial_mod_q - correction_mod_q) * P^-1 mod q_i`.
    /// Scheme-specific callers may prepare and scale `correction_mod_q` before
    /// applying this common final step.
    /// The function neither converts the correction nor allocates. Zero length
    /// requires empty data slices and performs no writes.
    ///
    /// # Panics
    ///
    /// Panics if either polynomial has the wrong length or if the derived `Q`
    /// polynomial length overflows `usize`.
    ///
    /// # Correctness
    ///
    /// Both slices must contain canonical residues in this instance's Q order.
    /// The caller owns the correction's mathematical source, sign and scaling;
    /// this method always subtracts it before multiplying by `P^-1`. Equal
    /// buffer lengths alone do not establish a compatible basis or a correct
    /// scheme-specific ModDown correction.
    pub fn approx_mod_down_from_correction_q_assign(
        &self,
        polynomial_mod_q: &mut [T],
        correction_mod_q: &[T],
        poly_length: usize,
    ) {
        let q_len = self
            .q_moduli_count()
            .checked_mul(poly_length)
            .expect("hybrid Q polynomial length overflow");
        assert_eq!(polynomial_mod_q.len(), q_len);
        assert_eq!(correction_mod_q.len(), q_len);

        self.mod_down_from_correction_q_kernel(polynomial_mod_q, correction_mod_q, poly_length);
    }

    /// Applies `(x_Q - lift_P) * P^-1` after either public ModDown entry checks
    /// both complete Q layouts. The ordered correction and inverse factors use
    /// this hybrid instance's Q basis; no conversion or allocation is needed.
    fn mod_down_from_correction_q_kernel(
        &self,
        polynomial_mod_q: &mut [T],
        correction_mod_q: &[T],
        poly_length: usize,
    ) {
        debug_assert_eq!(polynomial_mod_q.len(), correction_mod_q.len());
        if poly_length == 0 {
            return;
        }
        izip!(
            polynomial_mod_q.chunks_exact_mut(poly_length),
            correction_mod_q.chunks_exact(poly_length),
            self.q_base.moduli(),
            &self.inv_p_mod_q,
        )
        .for_each(|(q_limb, correction_q_limb, qi, &inv_p_mod_qi)| {
            q_limb.iter_mut().zip(correction_q_limb).for_each(
                |(output_mod_qi, &correction_mod_qi)| {
                    *output_mod_qi = qi.reduce_mul(
                        qi.reduce_sub(*output_mod_qi, correction_mod_qi),
                        inv_p_mod_qi,
                    );
                },
            );
        });
    }
}
