use aligned_vec::{AVec, avec};
use primus_factor::{FactorMul, ShoupFactor};
use primus_gcd::Xgcd;
use primus_reduce::FieldContext;
use primus_shape::PolyLength;

use crate::{
    NttError,
    ntt::{MonomialNttTable, NttTable, assert_ntt_length},
    reverse::reverse_lsbs,
    root::try_minimal_primitive_root,
};

use super::scalar;
#[cfg(target_arch = "x86_64")]
use super::{avx2::precompute::build_avx2_roots_u32, avx512::precompute::build_avx512_roots_u32};

/// Backend selector for `U32NttTable`.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum U32Backend {
    Scalar,
    /// AVX2 backend — available on x86_64 with `avx2` target feature.
    Avx2,
    /// AVX-512 backend — available on x86_64 with `avx512f` target feature.
    Avx512,
}

/// Specialized NTT table for `u32` coefficients.
///
/// Stores canonical roots and Barrett-32 preconditioners plus the packed root
/// layout required by the backend selected at construction.
///
/// # Constraints
///
/// - `q < 2^30` — ensures lazy ranges `[0, 4q)` fit in `u32`.
#[derive(Clone)]
pub struct U32NttTable {
    pub(super) poly_length: PolyLength,
    pub(super) q: u32,
    pub(super) two_q: u32,
    pub(super) inv_n: u32,
    pub(super) inv_n_precon: u32,
    /// `inv_n * inv_roots[n-1] mod q` — precomputed for the inverse final stage.
    pub(super) inv_n_w: u32,
    /// Shoup preconditioner for `inv_n_w`.
    pub(super) inv_n_w_precon: u32,

    /// Forward roots in bit-reversed order (size `n`).
    pub(super) roots: AVec<u32>,
    /// Barrett-32 preconditioners for `roots` (size `n`).
    pub(super) roots_precon: AVec<u32>,
    /// Inverse roots in bit-reversed order (size `n`).
    pub(super) inv_roots: AVec<u32>,
    /// Barrett-32 preconditioners for `inv_roots` (size `n`).
    pub(super) inv_roots_precon: AVec<u32>,

    /// AVX2 forward roots pre-expanded for T4/T2 vector loads (size ≈ n).
    #[cfg(target_arch = "x86_64")]
    pub(super) avx2_roots: AVec<u32>,
    /// AVX2 forward precon pre-expanded for T4/T2 vector loads.
    #[cfg(target_arch = "x86_64")]
    pub(super) avx2_roots_precon: AVec<u32>,
    /// AVX2 inverse roots pre-expanded for T4/T2 vector loads.
    #[cfg(target_arch = "x86_64")]
    pub(super) avx2_inv_roots: AVec<u32>,
    /// AVX2 inverse precon pre-expanded for T4/T2 vector loads.
    #[cfg(target_arch = "x86_64")]
    pub(super) avx2_inv_roots_precon: AVec<u32>,
    /// AVX-512 forward roots pre-expanded for T8/T4/T2/T1 vector loads (size ≈ 2n).
    #[cfg(target_arch = "x86_64")]
    pub(super) avx512_roots: AVec<u32>,
    /// AVX-512 forward precon pre-expanded for T8/T4/T2/T1 vector loads.
    #[cfg(target_arch = "x86_64")]
    pub(super) avx512_roots_precon: AVec<u32>,
    /// AVX-512 inverse roots pre-expanded for T8/T4/T2/T1 vector loads.
    #[cfg(target_arch = "x86_64")]
    pub(super) avx512_inv_roots: AVec<u32>,
    /// AVX-512 inverse precon pre-expanded for T8/T4/T2/T1 vector loads.
    #[cfg(target_arch = "x86_64")]
    pub(super) avx512_inv_roots_precon: AVec<u32>,

    #[cfg(target_arch = "x86_64")]
    backend: U32Backend,
}

/// Compute the modular inverse of `a` modulo `q`.
///
/// Uses `primus_gcd::Xgcd::gcdinv`, which specializes quotients `1`, `2`, and
/// `3` before falling back to integer division.
fn mod_inv(a: u32, q: u32) -> u32 {
    let (inv, gcd) = u32::gcdinv(a, q);
    assert_eq!(gcd, 1, "a={a} is not invertible modulo q={q}");
    inv
}

impl U32NttTable {
    /// Dispatch forward transform to the selected backend.
    ///
    /// `PolyLength` guarantees a complete SIMD block for every supported size.
    #[inline]
    fn dispatch_forward(&self, values: &mut [u32], output_mod_factor: u32) {
        assert_ntt_length(values.len(), self.poly_length.get());

        #[cfg(target_arch = "x86_64")]
        match self.backend {
            U32Backend::Avx2 => unsafe {
                return self.avx2_forward_transform(values, output_mod_factor);
            },
            U32Backend::Avx512 => unsafe {
                return self.avx512_forward_transform(values, output_mod_factor);
            },
            U32Backend::Scalar => {}
        }
        unsafe {
            self.scalar_forward_transform_unchecked(values, output_mod_factor);
        }
    }

    /// Dispatch inverse transform to the selected backend.
    #[inline]
    fn dispatch_inverse(&self, values: &mut [u32], output_mod_factor: u32) {
        assert_ntt_length(values.len(), self.poly_length.get());

        #[cfg(target_arch = "x86_64")]
        match self.backend {
            U32Backend::Avx2 => unsafe {
                return self.avx2_inverse_transform(values, output_mod_factor);
            },
            U32Backend::Avx512 => unsafe {
                return self.avx512_inverse_transform(values, output_mod_factor);
            },
            U32Backend::Scalar => {}
        }
        unsafe {
            self.scalar_inverse_transform_unchecked(values, output_mod_factor);
        }
    }
}

impl NttTable for U32NttTable {
    type ValueT = u32;

    fn new<M>(poly_length: PolyLength, modulus: M) -> Result<Self, NttError<Self::ValueT>>
    where
        M: FieldContext<Self::ValueT>,
    {
        let q = modulus.value();

        // Reject unsupported moduli: q < 2^30 required for lazy [0, 4q) range.
        if q >= 1 << crate::U32_NTT_MAX_MODULUS_BITS {
            return Err(NttError::ModulusTooLarge {
                modulus: q,
                max_bits: crate::U32_NTT_MAX_MODULUS_BITS,
            });
        }

        let log_n = poly_length.log_n();
        let root = try_minimal_primitive_root(log_n + 1, modulus)?;
        let n = poly_length.get();
        let two_q = q << 1;

        let inv_root = mod_inv(root, q);
        debug_assert_eq!(modulus.reduce_mul(root, inv_root), 1);

        // --- forward roots (bit-reversed) ---
        let root_sf = ShoupFactor::<u32>::new(root, q);
        let mut roots = avec![0u32; n];
        let mut power = 1;
        for i in 0..n {
            roots[reverse_lsbs(i, log_n)] = power;
            power = root_sf.factor_mul_modulo(power, q);
        }

        // --- inverse roots (bit-reversed, scrambled order) ---
        let inv_root_sf = ShoupFactor::<u32>::new(inv_root, q);
        let mut inv_roots = avec![0u32; n];
        inv_roots[0] = 1;
        let mut inv_power = inv_root;
        for i in 0..n - 1 {
            inv_roots[reverse_lsbs(i, log_n) + 1] = inv_power;
            inv_power = inv_root_sf.factor_mul_modulo(inv_power, q);
        }

        // --- Shoup preconditioners ---
        let roots_precon = AVec::from_iter(
            64,
            roots
                .iter()
                .map(|&w| ShoupFactor::<u32>::quotient_for(w, q)),
        );
        let inv_roots_precon = AVec::from_iter(
            64,
            inv_roots
                .iter()
                .map(|&w| ShoupFactor::<u32>::quotient_for(w, q)),
        );

        // --- inv_n = n^{-1} mod q ---
        let inv_n = mod_inv(n as u32, q);
        let inv_n_precon = ShoupFactor::<u32>::quotient_for(inv_n, q);

        // Precompute inv_n_w = inv_n * inv_roots[n-1] mod q for the inverse final stage.
        let last_w = unsafe { *inv_roots.get_unchecked(n - 1) };
        let inv_n_w = scalar::reduce_once(scalar::mul_mod_lazy(last_w, inv_n, inv_n_precon, q), q);
        let inv_n_w_precon = (((inv_n_w as u64) << 32) / q as u64) as u32;

        #[cfg(target_arch = "x86_64")]
        let backend = if is_x86_feature_detected!("avx512f") {
            U32Backend::Avx512
        } else if is_x86_feature_detected!("avx2") {
            U32Backend::Avx2
        } else {
            U32Backend::Scalar
        };
        // --- backend-specific pre-expanded root tables ---
        // Only build for the selected backend to save memory and init time.
        #[cfg(target_arch = "x86_64")]
        let use_avx2 = matches!(backend, U32Backend::Avx2);
        #[cfg(target_arch = "x86_64")]
        let use_avx512 = matches!(backend, U32Backend::Avx512);

        #[cfg(target_arch = "x86_64")]
        let (avx2_roots, avx2_roots_precon, avx2_inv_roots, avx2_inv_roots_precon) = if use_avx2 {
            let ar = build_avx2_roots_u32(n, &roots, false);
            let arp = build_avx2_roots_u32(n, &roots_precon, false);
            let air = build_avx2_roots_u32(n, &inv_roots, true);
            let airp = build_avx2_roots_u32(n, &inv_roots_precon, true);
            (ar, arp, air, airp)
        } else {
            (
                AVec::with_capacity(32, 0),
                AVec::with_capacity(32, 0),
                AVec::with_capacity(32, 0),
                AVec::with_capacity(32, 0),
            )
        };
        #[cfg(target_arch = "x86_64")]
        let (avx512_roots, avx512_roots_precon, avx512_inv_roots, avx512_inv_roots_precon) =
            if use_avx512 {
                let ar = build_avx512_roots_u32(n, &roots, false);
                let arp = build_avx512_roots_u32(n, &roots_precon, false);
                let air = build_avx512_roots_u32(n, &inv_roots, true);
                let airp = build_avx512_roots_u32(n, &inv_roots_precon, true);
                (ar, arp, air, airp)
            } else {
                (
                    AVec::with_capacity(64, 0),
                    AVec::with_capacity(64, 0),
                    AVec::with_capacity(64, 0),
                    AVec::with_capacity(64, 0),
                )
            };

        Ok(Self {
            poly_length,
            q,
            two_q,
            inv_n,
            inv_n_precon,
            inv_n_w,
            inv_n_w_precon,
            roots,
            roots_precon,
            inv_roots,
            inv_roots_precon,
            #[cfg(target_arch = "x86_64")]
            avx2_roots,
            #[cfg(target_arch = "x86_64")]
            avx2_roots_precon,
            #[cfg(target_arch = "x86_64")]
            avx2_inv_roots,
            #[cfg(target_arch = "x86_64")]
            avx2_inv_roots_precon,
            #[cfg(target_arch = "x86_64")]
            avx512_roots,
            #[cfg(target_arch = "x86_64")]
            avx512_roots_precon,
            #[cfg(target_arch = "x86_64")]
            avx512_inv_roots,
            #[cfg(target_arch = "x86_64")]
            avx512_inv_roots_precon,
            #[cfg(target_arch = "x86_64")]
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

    fn lazy_transform_slice(&self, poly: &mut [u32]) {
        self.dispatch_forward(poly, 4);
    }

    fn transform_slice(&self, poly: &mut [u32]) {
        self.dispatch_forward(poly, 1);
    }

    fn lazy_inverse_transform_slice(&self, values: &mut [u32]) {
        self.dispatch_inverse(values, 2);
    }

    fn inverse_transform_slice(&self, values: &mut [u32]) {
        self.dispatch_inverse(values, 1);
    }
}

impl MonomialNttTable for U32NttTable {
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
    use super::*;
    use crate::UintNttTable;
    use primus_modulus::BarrettModulus;

    // Compare each direction independently: a matching forward/inverse mistake
    // must not cancel in a round trip. Guarded subslices protect both boundaries.
    fn check_kernel(table: &U32NttTable) {
        let length = table.poly_length;
        let modulus = BarrettModulus::new(table.q);
        let reference = UintNttTable::<u32>::new(length, modulus).unwrap();
        for (inverse, output_factor) in [(false, 1), (false, 4), (true, 1), (true, 2)] {
            let q = table.q;
            let bound = output_factor * q;
            let mut guarded = vec![u32::MAX; length.get() + 2];
            let actual = &mut guarded[1..length.get() + 1];
            for (i, value) in actual.iter_mut().enumerate() {
                *value = [
                    0,
                    q - 1,
                    q,
                    2 * q - 1,
                    2 * q,
                    3 * q,
                    bound - 1,
                    17 * i as u32 + 31,
                ][i & 7]
                    % bound;
            }
            let mut expected: Vec<_> = actual.iter().map(|&value| value % table.q).collect();
            if inverse {
                table.dispatch_inverse(actual, output_factor);
                reference.inverse_transform_slice(&mut expected);
            } else {
                table.dispatch_forward(actual, output_factor);
                reference.transform_slice(&mut expected);
            }
            assert!(actual.iter().all(|&value| value < output_factor * table.q));
            assert_eq!(
                actual
                    .iter()
                    .map(|value| value % table.q)
                    .collect::<Vec<_>>(),
                expected,
                "N={}, inverse={inverse}, output_factor={output_factor}",
                length.get()
            );
            assert_eq!(
                (guarded[0], guarded[length.get() + 1]),
                (u32::MAX, u32::MAX)
            );
        }
    }

    #[test]
    fn scalar_kernel_matches_generic_boundaries() {
        for n in [32, 64] {
            let table = U32NttTable::new(PolyLength::new(n), BarrettModulus::new(1_073_692_673u32))
                .unwrap();
            #[cfg(target_arch = "x86_64")]
            let table = U32NttTable {
                backend: U32Backend::Scalar,
                ..table
            };
            check_kernel(&table);
        }
    }

    // Automatic selection hides AVX2 on AVX-512 hosts. Build the packed roots
    // for the explicitly selected backend, and enter it only on eligible CPUs.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn native_backends_match_generic_boundaries() {
        // N=32 is the minimum SIMD block; N=64 adds another broadcast stage
        // and multiple vectors per block. There is no recursive u32 schedule.
        for n in [32, 64] {
            let mut table =
                U32NttTable::new(PolyLength::new(n), BarrettModulus::new(1_073_692_673u32))
                    .unwrap();
            if is_x86_feature_detected!("avx2") {
                table.avx2_roots = build_avx2_roots_u32(n, &table.roots, false);
                table.avx2_roots_precon = build_avx2_roots_u32(n, &table.roots_precon, false);
                table.avx2_inv_roots = build_avx2_roots_u32(n, &table.inv_roots, true);
                table.avx2_inv_roots_precon =
                    build_avx2_roots_u32(n, &table.inv_roots_precon, true);
                table.backend = U32Backend::Avx2;
                check_kernel(&table);
            }
            if is_x86_feature_detected!("avx512f") {
                table.avx512_roots = build_avx512_roots_u32(n, &table.roots, false);
                table.avx512_roots_precon = build_avx512_roots_u32(n, &table.roots_precon, false);
                table.avx512_inv_roots = build_avx512_roots_u32(n, &table.inv_roots, true);
                table.avx512_inv_roots_precon =
                    build_avx512_roots_u32(n, &table.inv_roots_precon, true);
                table.backend = U32Backend::Avx512;
                check_kernel(&table);
            }
        }
    }
}
