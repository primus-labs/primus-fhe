use aligned_vec::{AVec, avec};
use primus_data::{DataMut, RawData};
use primus_factor::{FactorBase, FactorMul, ShoupFactor};
use primus_gcd::Xgcd;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

#[cfg(target_arch = "x86_64")]
use crate::constants::{HAS_AVX2, HAS_AVX512DQ, HAS_AVX512IFMA};
use crate::{NttError, ntt::NttTable, reverse::ReverseLsbs, root::PrimitiveRoot};

#[cfg(target_arch = "x86_64")]
use super::avx2::precompute::build_avx2_roots_u64;
use super::scalar;

/// Backend selector for `U64NttTable`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum U64Backend {
    Scalar,
    /// AVX2 backend — available on x86_64 with `avx2` target feature.
    #[cfg(target_arch = "x86_64")]
    Avx2,
    /// AVX-512 DQ backend — available on x86_64 with `avx512f` + `avx512dq`.
    #[cfg(target_arch = "x86_64")]
    Avx512Dq,
    /// AVX-512 IFMA backend — available on x86_64 with `avx512ifma`.
    #[cfg(target_arch = "x86_64")]
    Avx512Ifma,
}

/// Specialized NTT table for `u64` coefficients.
///
/// Stores roots and Barrett preconditioners in structure-of-arrays layout
/// for fast scalar and SIMD access.  Supports runtime dispatch to scalar,
/// AVX2, AVX-512 DQ, and AVX-512 IFMA backends.
///
/// # Constraints
///
/// - `q < 2^62` — ensures lazy ranges `[0, 4q)` fit in `u64`.
#[derive(Clone)]
pub struct U64NttTable {
    pub(super) n: usize,
    log_n: u32,
    pub(super) q: u64,
    pub(super) two_q: u64,
    /// True when `q < 2^30` — enables Barrett-32 multiply in scalar paths.
    pub(super) low_q: bool,
    root: u64,
    inv_root: u64,

    pub(super) inv_n: u64,
    pub(super) inv_n_precon32: u64,
    pub(super) inv_n_precon64: u64,
    /// `inv_n * inv_roots[n-1] mod q` — precomputed for the inverse final stage.
    pub(super) inv_n_w: u64,
    /// Shoup preconditioner for `inv_n_w`.
    pub(super) inv_n_w_precon32: u64,
    pub(super) inv_n_w_precon64: u64,

    /// Forward roots in bit-reversed order (size `n`).
    pub(super) roots: AVec<u64>,
    /// Barrett-32 preconditioners for `roots` (scalar fast path, `q < 2^30`).
    /// Always available — not gated by `target_arch`.
    pub(super) roots_precon32: AVec<u64>,
    /// Barrett-64 preconditioners for `roots` (size `n`).
    pub(super) roots_precon64: AVec<u64>,
    /// Inverse roots in bit-reversed order (size `n`).
    pub(super) inv_roots: AVec<u64>,
    /// Barrett-64 preconditioners for `inv_roots` (size `n`).
    pub(super) inv_roots_precon64: AVec<u64>,

    /// Ordinal powers: `[1, w, w^2, ..., w^(2n-1)]` (size `2n`).
    ordinal_roots: Vec<u64>,
    /// Bit-reversed index mapping (size `n`).
    reverse_lsbs: Vec<usize>,

    // ── AVX2 pre-expanded tables ───────────────────────────────────────
    /// AVX2 forward roots pre-expanded for T2/T1 vector loads (size ≈ n).
    #[cfg(target_arch = "x86_64")]
    pub(super) avx2_roots: AVec<u64>,
    /// AVX2 forward precon pre-expanded for T2/T1 vector loads.
    #[cfg(target_arch = "x86_64")]
    pub(super) avx2_roots_precon: AVec<u64>,
    /// AVX2 inverse roots pre-expanded for T2/T1 vector loads.
    #[cfg(target_arch = "x86_64")]
    pub(super) avx2_inv_roots: AVec<u64>,
    /// AVX2 inverse precon pre-expanded for T2/T1 vector loads.
    #[cfg(target_arch = "x86_64")]
    pub(super) avx2_inv_roots_precon: AVec<u64>,

    // ── AVX-512 pre-expanded tables (hexl-compatible layout) ───────────
    /// AVX-512 forward roots (T8/T4/T2/T1 layout, size ≈ 13n/8).
    #[cfg(target_arch = "x86_64")]
    avx512_roots: AVec<u64>,
    /// Barrett-32 preconditioners for `avx512_roots` (DQ-32 forward).
    #[cfg(target_arch = "x86_64")]
    avx512_roots_precon32: AVec<u64>,
    /// Barrett-52 preconditioners for `avx512_roots` (IFMA forward).
    #[cfg(target_arch = "x86_64")]
    avx512_roots_precon52: AVec<u64>,
    /// Barrett-64 preconditioners for `avx512_roots` (DQ-64 forward).
    #[cfg(target_arch = "x86_64")]
    avx512_roots_precon64: AVec<u64>,

    /// Barrett-32 preconditioners for `inv_roots` (scalar + DQ-32 inverse).
    /// Always available — not gated by `target_arch`.
    pub(super) inv_roots_precon32: AVec<u64>,
    /// Barrett-52 preconditioners for `inv_roots` (IFMA inverse).
    #[cfg(target_arch = "x86_64")]
    inv_roots_precon52: AVec<u64>,

    backend: U64Backend,
}

/// Compute the modular inverse of `a` modulo `q`.
///
/// Uses `primus_gcd::Xgcd::gcdinv` — an optimized binary GCD
/// that avoids division instructions.
fn mod_inv(a: u64, q: u64) -> u64 {
    debug_assert!(a < q);
    let (inv, gcd) = u64::gcdinv(a, q);
    assert_eq!(gcd, 1, "a={a} is not invertible modulo q={q}");
    inv
}

impl U64NttTable {
    /// Returns the modulus `q`.
    #[inline]
    pub fn modulus(&self) -> u64 {
        self.q
    }

    /// Returns `log2(N)`.
    #[inline]
    pub fn log_n(&self) -> u32 {
        self.log_n
    }

    /// Returns the polynomial length `N`.
    #[inline]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Returns the primitive `2N`-th root of unity.
    #[inline]
    pub fn root(&self) -> u64 {
        self.root
    }

    /// Returns the inverse of the primitive root.
    #[inline]
    pub fn inv_root(&self) -> u64 {
        self.inv_root
    }

    /// Returns the inverse of `N` modulo `q`.
    #[inline]
    pub fn inv_n(&self) -> u64 {
        self.inv_n
    }

    /// Dispatch forward transform to the selected backend.
    ///
    /// Priority: IFMA → DQ → AVX2 → scalar.
    fn dispatch_forward(&self, values: &mut [u64], output_mod_factor: u32) {
        #[cfg(target_arch = "x86_64")]
        if self.n >= 16 {
            use super::avx512::{
                internal::{IFMA_SHIFT_BITS, MAX_FWD_32_MODULUS, MAX_FWD_IFMA_MODULUS},
                transform::forward_transform_to_bit_reverse_avx512,
            };

            if matches!(self.backend, U64Backend::Avx512Ifma) && self.q < MAX_FWD_IFMA_MODULUS {
                return unsafe {
                    forward_transform_to_bit_reverse_avx512::<{ IFMA_SHIFT_BITS }>(
                        values,
                        self.q,
                        &self.avx512_roots,
                        &self.avx512_roots_precon52,
                        1,
                        output_mod_factor as u64,
                        0,
                        0,
                    )
                };
            }

            if matches!(self.backend, U64Backend::Avx512Dq | U64Backend::Avx512Ifma) {
                return if self.q < MAX_FWD_32_MODULUS {
                    unsafe {
                        forward_transform_to_bit_reverse_avx512::<32>(
                            values,
                            self.q,
                            &self.avx512_roots,
                            &self.avx512_roots_precon32,
                            1,
                            output_mod_factor as u64,
                            0,
                            0,
                        )
                    }
                } else {
                    unsafe {
                        forward_transform_to_bit_reverse_avx512::<64>(
                            values,
                            self.q,
                            &self.avx512_roots,
                            &self.avx512_roots_precon64,
                            1,
                            output_mod_factor as u64,
                            0,
                            0,
                        )
                    }
                };
            }

            // Skip AVX2 when q is small — scalar Barrett‑32 is faster than
            // AVX2 Barrett‑64 for these primes.
            if matches!(self.backend, U64Backend::Avx2) && !self.low_q {
                return unsafe { self.avx2_forward_transform(values, output_mod_factor) };
            }
        }

        if self.low_q {
            self.scalar_forward_transform::<32>(values, output_mod_factor);
        } else {
            self.scalar_forward_transform::<64>(values, output_mod_factor);
        }
    }

    /// Dispatch inverse transform to the selected backend.
    ///
    /// Priority: IFMA → DQ → AVX2 → scalar.
    fn dispatch_inverse(&self, values: &mut [u64], output_mod_factor: u32) {
        #[cfg(target_arch = "x86_64")]
        if self.n >= 16 {
            use super::avx512::{
                internal::{IFMA_SHIFT_BITS, MAX_INV_32_MODULUS, MAX_INV_IFMA_MODULUS},
                transform::inverse_transform_from_bit_reverse_avx512,
            };

            if matches!(self.backend, U64Backend::Avx512Ifma) && self.q < MAX_INV_IFMA_MODULUS {
                return unsafe {
                    inverse_transform_from_bit_reverse_avx512::<{ IFMA_SHIFT_BITS }>(
                        values,
                        self.q,
                        self.inv_n,
                        &self.inv_roots,
                        &self.inv_roots_precon52,
                        1,
                        output_mod_factor as u64,
                        0,
                        0,
                    )
                };
            }

            if matches!(self.backend, U64Backend::Avx512Dq | U64Backend::Avx512Ifma) {
                return if self.q < MAX_INV_32_MODULUS {
                    unsafe {
                        inverse_transform_from_bit_reverse_avx512::<32>(
                            values,
                            self.q,
                            self.inv_n,
                            &self.inv_roots,
                            &self.inv_roots_precon32,
                            1,
                            output_mod_factor as u64,
                            0,
                            0,
                        )
                    }
                } else {
                    unsafe {
                        inverse_transform_from_bit_reverse_avx512::<64>(
                            values,
                            self.q,
                            self.inv_n,
                            &self.inv_roots,
                            &self.inv_roots_precon64,
                            1,
                            output_mod_factor as u64,
                            0,
                            0,
                        )
                    }
                };
            }

            if matches!(self.backend, U64Backend::Avx2) && !self.low_q {
                return unsafe { self.avx2_inverse_transform(values, output_mod_factor) };
            }
        }

        if self.low_q {
            self.scalar_inverse_transform::<32>(values, output_mod_factor);
        } else {
            self.scalar_inverse_transform::<64>(values, output_mod_factor);
        }
    }
}

impl NttTable for U64NttTable {
    type ValueT = u64;

    fn new<M>(log_n: u32, modulus: M) -> Result<Self, NttError<Self::ValueT>>
    where
        M: FieldContext<Self::ValueT>,
    {
        let root = <u64 as PrimitiveRoot>::try_minimal_primitive_root(log_n + 1, modulus)?;
        let Some(q) = modulus.value() else {
            return Err(NttError::NttTableErr);
        };

        // Reject unsupported moduli: q < 2^62 required for lazy [0, 4q) range.
        if q >= 1 << 62 {
            return Err(NttError::ModulusTooLarge {
                modulus: q,
                max_bits: 62,
            });
        }

        let n = 1usize << log_n;
        let two_q = q << 1;
        let low_q = q < (1u64 << 30);

        // --- ordinal roots: [1, w, w^2, ..., w^(2n-1)] ---
        let root_sf = ShoupFactor::<u64>::new(root, q);
        let mut ordinal_roots = vec![0u64; n * 2];
        ordinal_roots[0] = 1;
        ordinal_roots[1] = root;
        let mut power = root;
        for dst in &mut ordinal_roots[2..] {
            power = root_sf.factor_mul_modulo(power, q);
            *dst = power;
        }

        let inv_root = *ordinal_roots.last().unwrap();
        debug_assert_eq!(modulus.reduce_mul(root, inv_root), 1);

        // --- bit-reversed index mapping ---
        let reverse_lsbs: Vec<usize> = (0..n).map(|i| i.reverse_lsbs(log_n)).collect();

        // --- forward roots (bit-reversed) ---
        let mut roots = avec![0u64; n];
        roots[0] = 1;
        for (&rp, &i) in ordinal_roots[0..n].iter().zip(reverse_lsbs.iter()) {
            roots[i] = rp;
        }

        // --- inverse roots (bit-reversed, scrambled order) ---
        let mut inv_roots = avec![0u64; n];
        inv_roots[0] = 1;
        for (&irp, &i) in ordinal_roots[n + 1..].iter().rev().zip(reverse_lsbs.iter()) {
            inv_roots[i + 1] = irp;
        }

        // --- Shoup preconditioners ---
        // Barrett-32 precons for the scalar fast path (q < 2^30).
        // Barrett-32 precons for scalar fast path (and reused by AVX-512 DQ-32
        // inverse).  Built unconditionally when q is small enough.
        let roots_precon32 = if low_q {
            super::avx512::precompute::build_barrett_vector(&roots, 32, q)
        } else {
            AVec::with_capacity(64, 0)
        };
        let inv_roots_precon32 = if low_q {
            super::avx512::precompute::build_barrett_vector(&inv_roots, 32, q)
        } else {
            AVec::with_capacity(64, 0)
        };
        let roots_precon64 = AVec::from_iter(
            64,
            roots
                .iter()
                .map(|&w| ShoupFactor::<u64>::quotient_for(w, q)),
        );
        let inv_roots_precon64 = AVec::from_iter(
            64,
            inv_roots
                .iter()
                .map(|&w| ShoupFactor::<u64>::quotient_for(w, q)),
        );

        // --- inv_n = n^{-1} mod q ---
        let inv_n = mod_inv(n as u64, q);
        let inv_n_precon64 = ShoupFactor::<u64>::quotient_for(inv_n, q);
        let inv_n_precon32 = if low_q {
            (inv_n << 32).wrapping_div(q)
        } else {
            0
        };

        // Precompute inv_n_w = inv_n * inv_roots[n-1] mod q for the inverse final stage.
        let last_w = unsafe { *inv_roots.get_unchecked(n - 1) };
        let inv_n_w =
            scalar::reduce_once(scalar::mul_mod_lazy(last_w, inv_n, inv_n_precon64, q), q);
        let inv_n_w_precon64 = ShoupFactor::<u64>::quotient_for(inv_n_w, q);
        let inv_n_w_precon32 = if low_q {
            (inv_n_w << 32).wrapping_div(q)
        } else {
            0
        };

        // --- backend selector (best available) ---
        #[cfg(target_arch = "x86_64")]
        let backend = {
            if *HAS_AVX512IFMA {
                U64Backend::Avx512Ifma
            } else if *HAS_AVX512DQ {
                U64Backend::Avx512Dq
            } else if *HAS_AVX2 {
                U64Backend::Avx2
            } else {
                U64Backend::Scalar
            }
        };
        #[cfg(not(target_arch = "x86_64"))]
        let backend = U64Backend::Scalar;

        // --- backend-specific pre-expanded root tables ---
        // AVX2 tables: needed for Avx2 (and kept empty for higher backends
        // since AVX-512 paths don't use the AVX2 root layout).
        #[cfg(target_arch = "x86_64")]
        let use_avx2 = matches!(backend, U64Backend::Avx2);
        #[cfg(target_arch = "x86_64")]
        let (avx2_roots, avx2_roots_precon, avx2_inv_roots, avx2_inv_roots_precon) = if use_avx2 {
            (
                build_avx2_roots_u64(n, &roots, false),
                build_avx2_roots_u64(n, &roots_precon64, false),
                build_avx2_roots_u64(n, &inv_roots, true),
                build_avx2_roots_u64(n, &inv_roots_precon64, true),
            )
        } else {
            (
                AVec::with_capacity(64, 0),
                AVec::with_capacity(64, 0),
                AVec::with_capacity(64, 0),
                AVec::with_capacity(64, 0),
            )
        };

        // AVX-512 tables: needed for Avx512Ifma/Avx512Dq (hexl-compatible layout).
        #[cfg(target_arch = "x86_64")]
        let use_avx512 = matches!(backend, U64Backend::Avx512Ifma | U64Backend::Avx512Dq);
        #[cfg(target_arch = "x86_64")]
        // Reuse the scalar inv_roots_precon32 if already built; otherwise
        // build it here for the AVX-512 DQ-32 inverse path.
        let (
            avx512_roots,
            avx512_roots_precon32,
            avx512_roots_precon52,
            avx512_roots_precon64,
            inv_roots_precon52,
        ) = if use_avx512 {
            let ar = super::avx512::precompute::build_avx512_root_powers(n, &roots);
            let arp32 = super::avx512::precompute::build_barrett_vector(&ar, 32, q);
            let arp52 = super::avx512::precompute::build_barrett_vector(&ar, 52, q);
            let arp64 = super::avx512::precompute::build_barrett_vector(&ar, 64, q);
            let irp52 = super::avx512::precompute::build_barrett_vector(&inv_roots, 52, q);
            (ar, arp32, arp52, arp64, irp52)
        } else {
            (
                AVec::with_capacity(64, 0),
                AVec::with_capacity(64, 0),
                AVec::with_capacity(64, 0),
                AVec::with_capacity(64, 0),
                AVec::with_capacity(64, 0),
            )
        };

        Ok(Self {
            n,
            log_n,
            q,
            two_q,
            low_q,
            root,
            inv_root,
            inv_n,
            inv_n_precon32,
            inv_n_precon64,
            inv_n_w,
            inv_n_w_precon32,
            inv_n_w_precon64,
            roots,
            roots_precon32,
            roots_precon64,
            inv_roots,
            inv_roots_precon64,
            ordinal_roots,
            reverse_lsbs,
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
            avx512_roots_precon32,
            #[cfg(target_arch = "x86_64")]
            avx512_roots_precon52,
            #[cfg(target_arch = "x86_64")]
            avx512_roots_precon64,
            inv_roots_precon32,
            #[cfg(target_arch = "x86_64")]
            inv_roots_precon52,
            backend,
        })
    }

    #[inline]
    fn poly_length(&self) -> usize {
        self.n
    }

    #[inline]
    fn transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
        &self,
        mut poly: Polynomial<S>,
    ) -> NttPolynomial<S> {
        self.transform_slice(poly.as_mut_slice());
        NttPolynomial::new(poly.0)
    }

    #[inline]
    fn inverse_transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
        &self,
        mut values: NttPolynomial<S>,
    ) -> Polynomial<S> {
        self.inverse_transform_slice(values.as_mut_slice());
        Polynomial::new(values.0)
    }

    #[inline]
    fn lazy_transform_slice(&self, poly: &mut [u64]) {
        debug_assert_eq!(poly.len(), self.n);
        self.dispatch_forward(poly, 4);
    }

    #[inline]
    fn transform_slice(&self, poly: &mut [u64]) {
        debug_assert_eq!(poly.len(), self.n);
        self.dispatch_forward(poly, 1);
    }

    #[inline]
    fn lazy_inverse_transform_slice(&self, values: &mut [u64]) {
        debug_assert_eq!(values.len(), self.n);
        self.dispatch_inverse(values, 2);
    }

    #[inline]
    fn inverse_transform_slice(&self, values: &mut [u64]) {
        debug_assert_eq!(values.len(), self.n);
        self.dispatch_inverse(values, 1);
    }

    fn transform_monomial(&self, coeff: u64, degree: usize, values: &mut [u64]) {
        if coeff == 0 {
            values.fill(0);
            return;
        }

        if degree == 0 {
            values.fill(coeff);
            return;
        }

        let n = self.n;
        let log_n = self.log_n;
        debug_assert_eq!(values.len(), n);

        let mask = usize::MAX >> (usize::BITS - log_n - 1);

        if coeff == 1 {
            values
                .iter_mut()
                .zip(&self.reverse_lsbs)
                .for_each(|(v, &i)| {
                    let index = ((2 * i + 1) * degree) & mask;
                    *v = unsafe { *self.ordinal_roots.get_unchecked(index) };
                });
        } else if coeff == self.q - 1 {
            values
                .iter_mut()
                .zip(&self.reverse_lsbs)
                .for_each(|(v, &i)| {
                    let index = (((2 * i + 1) * degree) & mask) ^ n;
                    *v = unsafe { *self.ordinal_roots.get_unchecked(index) };
                });
        } else {
            let coeff_sf = ShoupFactor::<u64>::new(coeff, self.q);
            values
                .iter_mut()
                .zip(&self.reverse_lsbs)
                .for_each(|(v, &i)| {
                    let index = ((2 * i + 1) * degree) & mask;
                    let w = unsafe { *self.ordinal_roots.get_unchecked(index) };
                    *v = coeff_sf.factor_mul_modulo(w, self.q);
                });
        }
    }

    fn transform_coeff_one_monomial(&self, degree: usize, values: &mut [u64]) {
        if degree == 0 {
            values.fill(1);
            return;
        }

        let n = self.n;
        let log_n = self.log_n;
        debug_assert_eq!(values.len(), n);

        let mask = usize::MAX >> (usize::BITS - log_n - 1);

        values
            .iter_mut()
            .zip(&self.reverse_lsbs)
            .for_each(|(v, &i)| {
                let index = ((2 * i + 1) * degree) & mask;
                *v = unsafe { *self.ordinal_roots.get_unchecked(index) };
            });
    }

    fn transform_coeff_minus_one_monomial(&self, degree: usize, values: &mut [u64]) {
        if degree == 0 {
            values.fill(self.q - 1);
            return;
        }

        let n = self.n;
        let log_n = self.log_n;
        debug_assert_eq!(values.len(), n);

        let mask = usize::MAX >> (usize::BITS - log_n - 1);

        values
            .iter_mut()
            .zip(&self.reverse_lsbs)
            .for_each(|(v, &i)| {
                let index = (((2 * i + 1) * degree) & mask) ^ n;
                *v = unsafe { *self.ordinal_roots.get_unchecked(index) };
            });
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
