pub(super) mod slice {
    //! Scalar helper kernels for one modulus chunk.

    use primus_factor::Factor;
    use primus_integer::FheUint;
    use primus_modulus::common::compact;

    /// Writes one centered small-value chunk for a single RNS modulus.
    ///
    /// `small_values.len()` and `residues.len()` must match. `residues` is the
    /// output chunk for one modulus. `half` is `ceil(small_value_modulus / 2)`
    /// and `temp` is `modulus - small_value_modulus` for that modulus.
    #[inline]
    pub(in crate::base) fn wrapping_decompose_chunk_to<T: FheUint>(
        small_values: &[T],
        residues: &mut [T],
        half: T,
        temp: T,
    ) {
        for (residue, &value) in residues.iter_mut().zip(small_values) {
            *residue = if value < half { value } else { temp + value };
        }
    }

    /// Adds one centered, scaled small-value chunk for a single RNS modulus.
    ///
    /// `small_values.len()` and `acc.len()` must match. `acc` is the
    /// accumulator chunk for one modulus and is not cleared. `factor` must be a
    /// factor for `modulus`. `half` and `temp` have the same meaning as in
    /// [`wrapping_decompose_chunk_to`].
    #[inline]
    pub(in crate::base) fn add_wrapping_decompose_chunk_scaled_assign<T, F>(
        small_values: &[T],
        acc: &mut [T],
        half: T,
        temp: T,
        modulus: T,
        factor: F,
    ) where
        T: FheUint,
        F: Factor<T>,
    {
        for (d, &value) in acc.iter_mut().zip(small_values) {
            let centered = if value < half { value } else { temp + value };
            compact::reduce_add_assign(modulus, d, factor.factor_mul_modulo(centered, modulus));
        }
    }
}

#[cfg(feature = "simd")]
pub(super) mod simd {
    //! SIMD helper kernels for one modulus chunk.

    use std::simd::cmp::{SimdOrd, SimdPartialOrd};

    use primus_factor::{Factor, FactorMul};
    use primus_integer::{FheUint, SimdArray, SimdMaskArray};

    /// Vectorized centered small-value decomposition for one RNS modulus.
    ///
    /// `small_values.len()` and `residues.len()` must match. Full SIMD lanes
    /// are processed here and any remainder is delegated to the scalar helper.
    /// `half` and `temp` have the same meaning as in the scalar helper.
    #[inline]
    pub(in crate::base) fn wrapping_decompose_chunk_to<T: FheUint>(
        small_values: &[T],
        residues: &mut [T],
        half: T,
        temp: T,
    ) {
        let half_simd = T::SimdT::splat(half);
        let temp_simd = T::SimdT::splat(temp);

        let (res_chunks, res_rem) = T::simd_as_chunks_mut(residues);
        let (val_chunks, val_rem) = T::simd_as_chunks(small_values);

        for (res, val) in res_chunks.iter_mut().zip(val_chunks) {
            let v = T::SimdT::from_array(*val);
            let mask = v.simd_lt(half_simd);
            *res = mask.select(v, temp_simd + v).to_array();
        }

        super::slice::wrapping_decompose_chunk_to(val_rem, res_rem, half, temp);
    }

    /// Vectorized centered, scaled accumulation for one RNS modulus.
    ///
    /// `small_values.len()` and `acc.len()` must match. Full SIMD lanes are
    /// accumulated here and any remainder is delegated to the scalar helper.
    /// `factor` must be a factor for `modulus`.
    #[inline]
    pub(in crate::base) fn add_wrapping_decompose_chunk_scaled_assign<T, F>(
        small_values: &[T],
        acc: &mut [T],
        half: T,
        temp: T,
        modulus: T,
        factor: F,
    ) where
        T: FheUint,
        F: Factor<T>,
    {
        let sh = T::SimdT::splat(half);
        let st = T::SimdT::splat(temp);
        let sm = T::SimdT::splat(modulus);
        let sf = F::simd_from_factor(factor);

        let (acc_chunks, acc_rem) = T::simd_as_chunks_mut(acc);
        let (val_chunks, val_rem) = T::simd_as_chunks(small_values);

        for (acc_chunk, val_chunk) in acc_chunks.iter_mut().zip(val_chunks) {
            let v = T::SimdT::from_array(*val_chunk);
            let mask = v.simd_lt(sh);
            let centered = mask.select(v, st + v);
            let product = sf.factor_mul_modulo(centered, sm);
            let acc_val = T::SimdT::from_array(*acc_chunk);
            let sum = acc_val + product;
            *acc_chunk = sum.simd_min(sum - sm).to_array();
        }

        super::slice::add_wrapping_decompose_chunk_scaled_assign(
            val_rem, acc_rem, half, temp, modulus, factor,
        );
    }
}
