use core::range::Range;

use primus_integer::FheUint;
use primus_reduce::FieldContext;

use crate::converter::FastConversionLimb;

use super::HybridRNSPartition;

impl<T, M> HybridRNSPartition<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Returns the minimum scratch length required by the approximate ModUp
    /// methods.
    #[must_use]
    #[inline]
    pub fn mod_up_scratch_len(&self, poly_length: usize) -> usize {
        self.mod_up_converter
            .fast_convert_array_scratch_len(poly_length)
    }

    /// Returns the number of moduli in the complete `Q || P` basis.
    #[inline]
    fn qp_moduli_count(&self) -> usize {
        self.mod_up_converter.output_moduli_count() + self.moduli_count()
    }

    /// Returns the active partition's element range and polynomial view.
    #[inline]
    fn partition_view<'a>(
        &self,
        polynomial_mod_q: &'a [T],
        poly_length: usize,
    ) -> (Range<usize>, &'a [T]) {
        let expected_input_len = self
            .q_moduli_count
            .checked_mul(poly_length)
            .expect("hybrid Q polynomial length overflow");
        assert_eq!(polynomial_mod_q.len(), expected_input_len);

        let partition_elements: Range<usize> =
            (self.q_range.start * poly_length..self.q_range.end * poly_length).into();
        let partition_polynomial = &polynomial_mod_q[partition_elements];
        (partition_elements, partition_polynomial)
    }

    /// Pairs complementary `QP` indices with their prepared conversion limbs.
    ///
    /// The converter output basis is constructed as
    /// `Q[..start] || Q[end..] || P`; this method is the single place that maps
    /// that order back into full `Q || P` indices.
    #[inline]
    fn approx_mod_up_complement_limbs<'a>(
        &'a self,
        partition_polynomial: &'a [T],
        poly_length: usize,
        scratch: &'a mut [T],
    ) -> impl Iterator<Item = (usize, FastConversionLimb<'a, T, M>)> + 'a {
        let qp_moduli_count = self.qp_moduli_count();
        let complement_indices = (0..self.q_range.start).chain(self.q_range.end..qp_moduli_count);
        let converted_limbs = self.mod_up_converter.fast_convert_array_limbs(
            partition_polynomial,
            poly_length,
            scratch,
        );

        complement_indices.zip(converted_limbs)
    }

    /// Extends this partition of a `Q`-basis polynomial into one complete
    /// `QP` hybrid digit.
    ///
    /// Both input and output use modulus-major layout. `scratch.len()` must be
    /// at least [`mod_up_scratch_len`](Self::mod_up_scratch_len). The partition
    /// limbs are copied exactly; all complementary `Q` and `P` limbs are
    /// produced by approximate RNS base conversion.
    /// Zero length requires empty input and output and performs no writes.
    ///
    /// # Panics
    ///
    /// Panics if an input, output, or scratch buffer has the wrong length, or
    /// if a derived polynomial length overflows `usize`.
    ///
    /// # Correctness
    ///
    /// Inputs must be canonical for this partition's ordered Q basis. The
    /// cross-modulus arithmetic requirements of [`crate::BaseConverter::fast_convert`]
    /// apply to the converted complement.
    pub fn approx_mod_up_to(
        &self,
        polynomial_mod_q: &[T],
        digit_mod_qp: &mut [T],
        poly_length: usize,
        scratch: &mut [T],
    ) {
        let qp_moduli_count = self.qp_moduli_count();
        let expected_digit_len = qp_moduli_count
            .checked_mul(poly_length)
            .expect("hybrid QP polynomial length overflow");
        assert_eq!(digit_mod_qp.len(), expected_digit_len);

        let (partition_elements, partition_polynomial) =
            self.partition_view(polynomial_mod_q, poly_length);
        if poly_length == 0 {
            return;
        }
        // Prepare and validate scratch before changing any digit limbs.
        let conversions =
            self.approx_mod_up_complement_limbs(partition_polynomial, poly_length, scratch);
        digit_mod_qp[partition_elements].copy_from_slice(partition_polynomial);

        for (qp_modulus_index, conversion) in conversions {
            let output_start = qp_modulus_index * poly_length;
            conversion.write_to(&mut digit_mod_qp[output_start..output_start + poly_length]);
        }
    }

    /// Produces the approximately converted complement limbs one at a time.
    ///
    /// This is the fused counterpart of [`approx_mod_up_to`](Self::approx_mod_up_to).
    /// It omits the partition's original `Q` limbs, allowing callers that
    /// already hold those limbs in another representation to reuse them
    /// directly. Each complementary limb is written to `output_limb` before
    /// `consume` is called with its index in the full `QP` basis.
    ///
    /// `output_limb.len()` must equal `poly_length`. The callback may modify the
    /// limb; the next conversion overwrites it completely. The operation does
    /// not allocate.
    /// Zero length requires empty input and output and does not invoke `consume`.
    ///
    /// # Panics
    ///
    /// Panics if an input, output, or scratch buffer has the wrong length, or
    /// if a derived polynomial length overflows `usize`.
    /// A panicking callback may leave scratch and the reusable limb modified;
    /// previously consumed limbs are not rolled back.
    ///
    /// # Correctness
    ///
    /// The ordered-basis and arithmetic requirements of
    /// [`approx_mod_up_to`](Self::approx_mod_up_to) apply.
    pub fn for_each_approx_mod_up_complement_limb<F>(
        &self,
        polynomial_mod_q: &[T],
        output_limb: &mut [T],
        poly_length: usize,
        scratch: &mut [T],
        mut consume: F,
    ) where
        F: FnMut(usize, &mut [T]),
    {
        assert_eq!(output_limb.len(), poly_length);
        let (_, partition_polynomial) = self.partition_view(polynomial_mod_q, poly_length);
        if poly_length == 0 {
            return;
        }
        self.approx_mod_up_complement_limbs(partition_polynomial, poly_length, scratch)
            .for_each(|(qp_modulus_index, conversion)| {
                conversion.write_to(output_limb);
                consume(qp_modulus_index, output_limb);
            });
    }
}
