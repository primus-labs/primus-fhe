use aligned_vec::{AVec, avec};
use primus_factor::{FactorMul, MultiplyFactor, ShoupFactor};
use primus_gcd::Xgcd;
use primus_reduce::FieldContext;
use primus_shape::PolyLength;

use crate::{
    NttError,
    ntt::{MonomialNttTable, NttTable, assert_ntt_length},
    reverse::reverse_lsbs,
    root::try_minimal_primitive_root,
};

use super::precompute::U64Backend;
/// Backend-specific constants for the fused final inverse stage.
#[derive(Clone, Copy)]
pub(super) struct InverseFinalScale {
    pub(super) inv_n: u64,
    pub(super) inv_n_precon: u64,
    pub(super) inv_n_w: u64,
    pub(super) inv_n_w_precon: u64,
}

/// Specialized NTT table for `u64` coefficients.
///
/// Stores canonical roots and only the preconditioners and packed forward-root
/// layout required by the backend selected at construction. Supports scalar,
/// AVX2, AVX-512 DQ, and AVX-512 IFMA kernels.
///
/// # Constraints
///
/// - `q < 2^62` — ensures lazy ranges `[0, 4q)` fit in `u64`.
#[derive(Clone)]
pub struct U64NttTable {
    pub(super) poly_length: PolyLength,
    pub(super) q: u64,
    pub(super) two_q: u64,

    pub(super) inverse_final_scale: InverseFinalScale,

    /// Forward roots in bit-reversed order (size `n`).
    pub(super) roots: AVec<u64>,
    /// Inverse roots in bit-reversed order (size `n`).
    pub(super) inv_roots: AVec<u64>,
    backend: U64Backend,
}

/// Compute the modular inverse of `a` modulo `q`.
///
/// Uses `primus_gcd::Xgcd::gcdinv`, which specializes quotients `1`, `2`, and
/// `3` before falling back to integer division.
fn mod_inv(a: u64, q: u64) -> u64 {
    let (inv, gcd) = u64::gcdinv(a, q);
    assert_eq!(gcd, 1, "a={a} is not invertible modulo q={q}");
    inv
}

impl U64NttTable {
    /// Dispatch forward transform to the selected backend.
    fn dispatch_forward(&self, values: &mut [u64], input_mod_factor: u32, output_mod_factor: u32) {
        assert_ntt_length(values.len(), self.poly_length.get());

        #[cfg(target_arch = "x86_64")]
        use super::avx512::{
            internal::IFMA_SHIFT_BITS, transform::forward_transform_to_bit_reverse_avx512,
        };
        #[cfg(not(target_arch = "x86_64"))]
        let _ = input_mod_factor;

        // SAFETY: construction binds each precomputation to this table's roots,
        // modulus and width, and selects SIMD only when the CPU supports it.
        // Length is checked above. Wrappers fix the factors and rely on the
        // caller upholding NttTable's coefficient-range contract.
        match &self.backend {
            U64Backend::Scalar32(precomputation) => unsafe {
                self.scalar_forward_transform_unchecked::<32>(
                    values,
                    output_mod_factor,
                    precomputation,
                );
            },
            U64Backend::Scalar64(precomputation) => unsafe {
                self.scalar_forward_transform_unchecked::<64>(
                    values,
                    output_mod_factor,
                    precomputation,
                );
            },
            #[cfg(target_arch = "x86_64")]
            U64Backend::Avx2(precomputation) => unsafe {
                self.avx2_forward_transform(values, output_mod_factor, precomputation);
            },
            #[cfg(target_arch = "x86_64")]
            U64Backend::Avx512Dq32(precomputation) => unsafe {
                forward_transform_to_bit_reverse_avx512::<32>(
                    values,
                    self.q,
                    &precomputation.roots,
                    &precomputation.roots_precon,
                    input_mod_factor as u64,
                    output_mod_factor as u64,
                    0,
                    0,
                );
            },
            #[cfg(target_arch = "x86_64")]
            U64Backend::Avx512Dq64(precomputation) => unsafe {
                forward_transform_to_bit_reverse_avx512::<64>(
                    values,
                    self.q,
                    &precomputation.roots,
                    &precomputation.roots_precon,
                    input_mod_factor as u64,
                    output_mod_factor as u64,
                    0,
                    0,
                );
            },
            #[cfg(target_arch = "x86_64")]
            U64Backend::Avx512Ifma52(precomputation) => unsafe {
                forward_transform_to_bit_reverse_avx512::<{ IFMA_SHIFT_BITS }>(
                    values,
                    self.q,
                    &precomputation.roots,
                    &precomputation.roots_precon,
                    input_mod_factor as u64,
                    output_mod_factor as u64,
                    0,
                    0,
                );
            },
        }
    }

    /// Dispatch inverse transform to the selected backend.
    fn dispatch_inverse(&self, values: &mut [u64], input_mod_factor: u32, output_mod_factor: u32) {
        assert_ntt_length(values.len(), self.poly_length.get());

        #[cfg(target_arch = "x86_64")]
        use super::avx512::{
            internal::IFMA_SHIFT_BITS, transform::inverse_transform_from_bit_reverse_avx512,
        };
        #[cfg(not(target_arch = "x86_64"))]
        let _ = input_mod_factor;

        // SAFETY: construction binds each precomputation to this table's roots,
        // modulus and width, and selects SIMD only when the CPU supports it.
        // Length is checked above. Wrappers fix the factors and rely on the
        // caller upholding NttTable's coefficient-range contract.
        match &self.backend {
            U64Backend::Scalar32(precomputation) => unsafe {
                self.scalar_inverse_transform_unchecked::<32>(
                    values,
                    output_mod_factor,
                    precomputation,
                );
            },
            U64Backend::Scalar64(precomputation) => unsafe {
                self.scalar_inverse_transform_unchecked::<64>(
                    values,
                    output_mod_factor,
                    precomputation,
                );
            },
            #[cfg(target_arch = "x86_64")]
            U64Backend::Avx2(precomputation) => unsafe {
                self.avx2_inverse_transform(values, output_mod_factor, precomputation);
            },
            #[cfg(target_arch = "x86_64")]
            U64Backend::Avx512Dq32(precomputation) => unsafe {
                inverse_transform_from_bit_reverse_avx512::<32>(
                    values,
                    self.q,
                    &self.inverse_final_scale,
                    &self.inv_roots,
                    &precomputation.inv_roots_precon,
                    input_mod_factor as u64,
                    output_mod_factor as u64,
                    0,
                    0,
                );
            },
            #[cfg(target_arch = "x86_64")]
            U64Backend::Avx512Dq64(precomputation) => unsafe {
                inverse_transform_from_bit_reverse_avx512::<64>(
                    values,
                    self.q,
                    &self.inverse_final_scale,
                    &self.inv_roots,
                    &precomputation.inv_roots_precon,
                    input_mod_factor as u64,
                    output_mod_factor as u64,
                    0,
                    0,
                );
            },
            #[cfg(target_arch = "x86_64")]
            U64Backend::Avx512Ifma52(precomputation) => unsafe {
                inverse_transform_from_bit_reverse_avx512::<{ IFMA_SHIFT_BITS }>(
                    values,
                    self.q,
                    &self.inverse_final_scale,
                    &self.inv_roots,
                    &precomputation.inv_roots_precon,
                    input_mod_factor as u64,
                    output_mod_factor as u64,
                    0,
                    0,
                );
            },
        }
    }
}

impl NttTable for U64NttTable {
    type ValueT = u64;

    fn new<M>(poly_length: PolyLength, modulus: M) -> Result<Self, NttError<Self::ValueT>>
    where
        M: FieldContext<Self::ValueT>,
    {
        let q = modulus.value();

        // Reject unsupported moduli: q < 2^62 required for lazy [0, 4q) range.
        if q >= 1 << crate::U64_NTT_MAX_MODULUS_BITS {
            return Err(NttError::ModulusTooLarge {
                modulus: q,
                max_bits: crate::U64_NTT_MAX_MODULUS_BITS,
            });
        }

        let log_n = poly_length.log_n();
        let root = try_minimal_primitive_root(log_n + 1, modulus)?;
        let n = poly_length.get();
        let two_q = q << 1;
        let inv_root = mod_inv(root, q);
        debug_assert_eq!(modulus.reduce_mul(root, inv_root), 1);

        // --- forward roots (bit-reversed) ---
        let root_sf = ShoupFactor::<u64>::new(root, q);
        let mut roots = avec![0u64; n];
        let mut power = 1;
        for i in 0..n {
            roots[reverse_lsbs(i, log_n)] = power;
            power = root_sf.factor_mul_modulo(power, q);
        }

        // --- inverse roots (bit-reversed, scrambled order) ---
        let inv_root_sf = ShoupFactor::<u64>::new(inv_root, q);
        let mut inv_roots = avec![0u64; n];
        inv_roots[0] = 1;
        let mut inv_power = inv_root;
        for i in 0..n - 1 {
            inv_roots[reverse_lsbs(i, log_n) + 1] = inv_power;
            inv_power = inv_root_sf.factor_mul_modulo(inv_power, q);
        }

        let backend = U64Backend::new(q, &roots, &inv_roots);
        let inverse_bit_shift = backend.bit_shift();

        // Constants for the backend's fused final inverse stage.
        let inv_n = mod_inv(n as u64, q);
        let last_w = unsafe { *inv_roots.get_unchecked(n - 1) };
        let inv_n_w = modulus.reduce_mul(inv_n, last_w);
        let inverse_final_scale = InverseFinalScale {
            inv_n,
            inv_n_precon: MultiplyFactor::new(inv_n, inverse_bit_shift, q).quotient(),
            inv_n_w,
            inv_n_w_precon: MultiplyFactor::new(inv_n_w, inverse_bit_shift, q).quotient(),
        };

        Ok(Self {
            poly_length,
            q,
            two_q,
            inverse_final_scale,
            roots,
            inv_roots,
            backend,
        })
    }

    #[inline]
    fn poly_length(&self) -> PolyLength {
        self.poly_length
    }

    #[inline]
    fn modulus(&self) -> Self::ValueT {
        self.q
    }

    #[inline]
    fn lazy_transform_slice(&self, poly: &mut [u64]) {
        self.dispatch_forward(poly, 4, 4);
    }

    #[inline]
    fn transform_slice(&self, poly: &mut [u64]) {
        self.dispatch_forward(poly, 1, 1);
    }

    #[inline]
    fn lazy_inverse_transform_slice(&self, values: &mut [u64]) {
        self.dispatch_inverse(values, 2, 2);
    }

    #[inline]
    fn inverse_transform_slice(&self, values: &mut [u64]) {
        self.dispatch_inverse(values, 1, 1);
    }
}

impl MonomialNttTable for U64NttTable {
    #[inline]
    fn root_powers(&self) -> &[Self::ValueT] {
        &self.roots
    }

    #[inline]
    fn inv_root_powers(&self) -> &[Self::ValueT] {
        &self.inv_roots
    }
}

#[cfg(test)]
mod tests {
    use super::super::precompute::ScalarPrecomputation;
    use super::*;
    use crate::UintNttTable;
    use primus_modulus::BarrettModulus;

    // Exercise an explicit backend independently of automatic host selection,
    // comparing lazy range boundaries against the generic canonical transform.
    fn check_kernel(table: &mut U64NttTable, backend: U64Backend) {
        let q = table.q;
        let length = table.poly_length;
        let reference = UintNttTable::<u64>::new(length, BarrettModulus::new(q)).unwrap();
        let bits = backend.bit_shift();
        let scale = &mut table.inverse_final_scale;
        scale.inv_n_precon = MultiplyFactor::new(scale.inv_n, bits, q).quotient();
        scale.inv_n_w_precon = MultiplyFactor::new(scale.inv_n_w, bits, q).quotient();
        table.backend = backend;

        for (inverse, output_factor) in [(false, 1), (false, 4), (true, 1), (true, 2)] {
            let bound = if inverse { 2 * q } else { 4 * q };
            let mut actual: Vec<_> = (0..length.get())
                .map(|i| [0, q - 1, q, bound - 1 - i as u64][i % 4])
                .collect();
            let mut expected: Vec<_> = actual.iter().map(|&value| value % q).collect();
            if inverse {
                table.dispatch_inverse(&mut actual, 2, output_factor);
            } else {
                table.dispatch_forward(&mut actual, 4, output_factor);
            }
            if inverse {
                reference.inverse_transform_slice(&mut expected);
            } else {
                reference.transform_slice(&mut expected);
            }
            assert!(
                actual
                    .iter()
                    .all(|&value| value < u64::from(output_factor) * q)
            );
            assert_eq!(
                actual.iter().map(|value| value % q).collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn scalar_kernels_match_generic_at_the_supported_minimum() {
        for (q, bits) in [(1_073_692_673, 32), (1_152_921_504_606_830_593, 64)] {
            let mut table = U64NttTable::new(PolyLength::new(32), BarrettModulus::new(q)).unwrap();
            let backend = if bits == 32 {
                U64Backend::Scalar32(ScalarPrecomputation::new::<32>(
                    q,
                    &table.roots,
                    &table.inv_roots,
                ))
            } else {
                U64Backend::Scalar64(ScalarPrecomputation::new::<64>(
                    q,
                    &table.roots,
                    &table.inv_roots,
                ))
            };
            check_kernel(&mut table, backend);
        }
    }

    // Automatic selection can hide DQ32 or AVX2 behind IFMA on the same host.
    // Verify every eligible precomputation/dispatch pair at the minimum length.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn native_backends_match_generic_at_the_supported_minimum() {
        use super::super::avx512::internal::IFMA_SHIFT_BITS;
        use super::super::precompute::{Avx2Precomputation, Avx512Precomputation};

        let mut small =
            U64NttTable::new(PolyLength::new(32), BarrettModulus::new(1_073_692_673)).unwrap();
        let mut large = U64NttTable::new(
            PolyLength::new(32),
            BarrettModulus::new(1_152_921_504_606_830_593),
        )
        .unwrap();
        if is_x86_feature_detected!("avx2") {
            let backend = U64Backend::Avx2(Avx2Precomputation::new(
                large.q,
                &large.roots,
                &large.inv_roots,
            ));
            check_kernel(&mut large, backend);
        }
        if is_x86_feature_detected!("avx512dq") {
            let backend = U64Backend::Avx512Dq32(Avx512Precomputation::new::<32>(
                small.q,
                &small.roots,
                &small.inv_roots,
            ));
            check_kernel(&mut small, backend);
            let backend = U64Backend::Avx512Dq64(Avx512Precomputation::new::<64>(
                large.q,
                &large.roots,
                &large.inv_roots,
            ));
            check_kernel(&mut large, backend);
            if is_x86_feature_detected!("avx512ifma") {
                let backend = U64Backend::Avx512Ifma52(Avx512Precomputation::new::<
                    { IFMA_SHIFT_BITS },
                >(
                    small.q, &small.roots, &small.inv_roots
                ));
                check_kernel(&mut small, backend);
            }
        }
    }
}
