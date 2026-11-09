use itertools::izip;
use primus_factor::Factor;
use primus_integer::FheUint;
use primus_reduce::FieldContext;

use super::RNSBase;
#[cfg(feature = "simd")]
use super::small_kernels::simd;
#[cfg(not(feature = "simd"))]
use super::small_kernels::slice;
use crate::{ResidueFactors, Residues};

impl<T, M> RNSBase<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Decomposes one small value with centered wrapping semantics.
    ///
    /// The returned vector has `moduli_count()` residues in basis order.
    /// Values below `ceil(small_value_modulus / 2)` are nonnegative; other
    /// values are lifted as negative representatives. For modulus `2`, both
    /// `0` and `1` are preserved, so `1` is not interpreted as `-1`.
    ///
    /// # Correctness
    ///
    /// `value` must be reduced modulo `small_value_modulus`, which must be
    /// nonzero and no larger than every RNS modulus.
    #[must_use]
    pub fn wrapping_decompose(&self, value: T, small_value_modulus: T) -> Residues<Vec<T>> {
        Residues(
            match negative_representative_magnitude(value, small_value_modulus) {
                Some(magnitude) => self
                    .moduli_values()
                    .iter()
                    .map(|&modulus| modulus - magnitude)
                    .collect(),
                None => vec![value; self.moduli_count()],
            },
        )
    }

    /// Writes [`wrapping_decompose`](Self::wrapping_decompose) into caller-provided storage.
    ///
    /// Fully overwrites `residues` in basis order without allocation.
    ///
    /// # Panics
    ///
    /// Panics if `residues.len()` does not equal `moduli_count()`.
    ///
    /// # Correctness
    ///
    /// The value and small-modulus requirements of
    /// [`wrapping_decompose`](Self::wrapping_decompose) apply.
    pub fn wrapping_decompose_to(
        &self,
        value: T,
        Residues(residues): Residues<&mut [T]>,
        small_value_modulus: T,
    ) {
        assert_eq!(self.moduli_count(), residues.len());

        match negative_representative_magnitude(value, small_value_modulus) {
            Some(magnitude) => {
                for (&modulus, residue) in self.moduli_values().iter().zip(residues) {
                    *residue = modulus - magnitude;
                }
            }
            None => residues.fill(value),
        }
    }

    /// Decomposes many small values into a flattened multi-residue layout.
    ///
    /// Each value is expected to be reduced modulo `small_value_modulus`.
    /// The centered rule is the same as in [`wrapping_decompose`](Self::wrapping_decompose).
    /// When `small_value_modulus == 2`, the binary values `0` and `1` are
    /// preserved directly; `1` is not interpreted as `-1`.
    ///
    /// `multi_residues.len()` must equal
    /// `moduli_count() * small_values.len()` and is written in modulus-major
    /// layout: chunk `i` receives all values reduced modulo `moduli()[i]`.
    ///
    /// Overwrites the output without allocation. Empty input requires empty
    /// output and performs no writes.
    ///
    /// # Panics
    ///
    /// Panics if the output length does not match the stated layout.
    /// Debug builds also check that the small modulus is below every RNS modulus.
    ///
    /// # Correctness
    ///
    /// Input values must be canonical modulo `small_value_modulus`, which
    /// must be nonzero and smaller than every RNS modulus.
    pub fn wrapping_decompose_small_values_to(
        &self,
        small_values: &[T],
        multi_residues: &mut [T],
        small_value_modulus: T,
    ) {
        let value_count = small_values.len();
        assert_eq!(multi_residues.len(), self.moduli_count() * value_count);
        debug_assert!(
            self.moduli_values()
                .iter()
                .copied()
                .all(|m| m > small_value_modulus)
        );
        if value_count == 0 {
            return;
        }

        if small_value_modulus != T::TWO {
            let half = small_value_modulus / T::TWO + (small_value_modulus & T::ONE);
            for (residues, modulus) in multi_residues
                .chunks_exact_mut(value_count)
                .zip(self.moduli_values().iter().copied())
            {
                let temp = modulus - small_value_modulus;

                #[cfg(not(feature = "simd"))]
                slice::wrapping_decompose_chunk_to(small_values, residues, half, temp);

                #[cfg(feature = "simd")]
                simd::wrapping_decompose_chunk_to(small_values, residues, half, temp);
            }
        } else {
            for residues in multi_residues.chunks_exact_mut(value_count) {
                residues.copy_from_slice(small_values);
            }
        }
    }

    /// Fused centered decomposition, scaling, and accumulation for small values.
    ///
    /// Each value is expected to be reduced modulo `small_value_modulus`, which
    /// must be smaller than every RNS modulus. When `small_value_modulus == 2`,
    /// the binary values `0` and `1` are preserved directly; `1` is not
    /// interpreted as `-1` before scaling.
    ///
    /// `acc.len()` must equal `moduli_count() * small_values.len()` and uses
    /// modulus-major layout. The function adds into the existing contents of
    /// `acc`; it does not clear the buffer first.
    ///
    /// `factors.len()` must equal `moduli_count()`. Factor `i` is used for the
    /// chunk modulo `moduli()[i]`.
    /// No temporary decomposition is allocated. Empty input requires empty
    /// `acc` and performs no writes; factors must still match the basis length.
    ///
    /// # Panics
    ///
    /// Panics if the accumulator or factor count does not match the stated layout.
    /// Debug builds also check that the small modulus is below every RNS modulus.
    ///
    /// # Correctness
    ///
    /// Inputs must be canonical modulo the nonzero `small_value_modulus`, which
    /// must be smaller than every RNS modulus. Accumulator entries must be
    /// canonical for their corresponding moduli. Each factor must satisfy
    /// [`Factor`]'s arithmetic contract for that modulus.
    pub fn add_wrapping_decompose_small_values_scaled_assign<F: Factor<T>>(
        &self,
        small_values: &[T],
        acc: &mut [T],
        small_value_modulus: T,
        factors: ResidueFactors<&[F]>,
    ) {
        let value_count = small_values.len();
        assert_eq!(acc.len(), self.moduli_count() * value_count);
        assert_eq!(factors.len(), self.moduli_count());
        debug_assert!(
            self.moduli_values()
                .iter()
                .copied()
                .all(|m| m > small_value_modulus)
        );

        if value_count == 0 {
            return;
        }

        if small_value_modulus != T::TWO {
            let half = small_value_modulus / T::TWO + (small_value_modulus & T::ONE);
            izip!(
                acc.chunks_exact_mut(value_count),
                self.moduli_values().iter().copied(),
                factors.iter(),
            )
            .for_each(|(acc_chunk, modulus, &factor)| {
                let temp = modulus - small_value_modulus;

                #[cfg(not(feature = "simd"))]
                slice::add_wrapping_decompose_chunk_scaled_assign(
                    small_values,
                    acc_chunk,
                    half,
                    temp,
                    modulus,
                    factor,
                );

                #[cfg(feature = "simd")]
                simd::add_wrapping_decompose_chunk_scaled_assign(
                    small_values,
                    acc_chunk,
                    half,
                    temp,
                    modulus,
                    factor,
                );
            });
        } else {
            izip!(
                acc.chunks_exact_mut(value_count),
                self.moduli_values().iter().copied(),
                factors.iter(),
            )
            .for_each(|(acc_chunk, modulus, &factor)| {
                factor.add_factor_mul_slice_assign(acc_chunk, small_values, modulus);
            });
        }
    }

    /// Fused unsigned decomposition, scaling, and accumulation for small values.
    ///
    /// Unlike
    /// [`add_wrapping_decompose_small_values_scaled_assign`](Self::add_wrapping_decompose_small_values_scaled_assign),
    /// this uses each input value directly as a residue under every modulus,
    /// without centered lifting. Callers should pass values that are already
    /// valid residues for all basis moduli.
    ///
    /// `acc.len()` must equal `moduli_count() * small_values.len()` and uses
    /// modulus-major layout. The function adds into the existing contents of
    /// `acc`.
    ///
    /// `factors.len()` must equal `moduli_count()`. Factor `i` is used for the
    /// chunk modulo `moduli()[i]`.
    /// The function neither clears `acc` nor allocates temporary storage.
    /// Empty input requires empty `acc` and performs no writes; factors must
    /// still match the basis length.
    ///
    /// # Panics
    ///
    /// Panics if the accumulator or factor count does not match the stated layout.
    ///
    /// # Correctness
    ///
    /// Both input and accumulator entries must be canonical for their
    /// corresponding moduli. Each factor must satisfy [`Factor`]'s arithmetic
    /// contract for that modulus.
    pub fn add_decompose_small_values_scaled_assign<F: Factor<T>>(
        &self,
        small_values: &[T],
        acc: &mut [T],
        factors: ResidueFactors<&[F]>,
    ) {
        let value_count = small_values.len();
        assert_eq!(acc.len(), self.moduli_count() * value_count);
        assert_eq!(factors.len(), self.moduli_count());

        if value_count == 0 {
            return;
        }

        izip!(
            acc.chunks_exact_mut(value_count),
            self.moduli_values().iter().copied(),
            factors.iter(),
        )
        .for_each(|(acc_chunk, modulus, &factor)| {
            factor.add_factor_mul_slice_assign(acc_chunk, small_values, modulus);
        });
    }
}

/// Chooses the scalar representative once, independently of the destination
/// basis. Binary `1` stays positive; otherwise a negative representative has
/// magnitude `t - value` and lifts to `q_i - magnitude` in every modulus.
#[inline]
fn negative_representative_magnitude<T: FheUint>(value: T, small_value_modulus: T) -> Option<T> {
    let half = small_value_modulus / T::TWO + (small_value_modulus & T::ONE);
    if small_value_modulus != T::TWO && value >= half {
        Some(small_value_modulus - value)
    } else {
        None
    }
}
