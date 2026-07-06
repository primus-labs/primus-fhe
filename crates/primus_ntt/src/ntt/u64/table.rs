use aligned_vec::{AVec, avec};
use primus_data::{DataMut, RawData};
use primus_factor::{FactorBase, FactorMul, ShoupFactor};
use primus_gcd::Xgcd;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

#[cfg(target_arch = "x86_64")]
use crate::constants::{HAS_AVX2, HAS_AVX512DQ, HAS_AVX512IFMA};
use crate::{NttError, ntt::NttTable, reverse::ReverseLsbs, root::PrimitiveRoot};

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
pub struct U64NttTable {
    pub(super) n: usize,
    log_n: u32,
    pub(super) q: u64,
    pub(super) two_q: u64,
    root: u64,
    inv_root: u64,

    pub(super) inv_n: u64,
    pub(super) inv_n_precon: u64,
    /// `inv_n * inv_roots[n-1] mod q` — precomputed for the inverse final stage.
    pub(super) inv_n_w: u64,
    /// Shoup preconditioner for `inv_n_w`.
    pub(super) inv_n_w_precon: u64,

    /// Forward roots in bit-reversed order (size `n`).
    pub(super) roots: AVec<u64>,
    /// Barrett-64 preconditioners for `roots` (size `n`).
    pub(super) roots_precon: AVec<u64>,
    /// Inverse roots in bit-reversed order (size `n`).
    pub(super) inv_roots: AVec<u64>,
    /// Barrett-64 preconditioners for `inv_roots` (size `n`).
    pub(super) inv_roots_precon: AVec<u64>,

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

    /// Barrett-32 preconditioners for `inv_roots` (DQ-32 inverse).
    #[cfg(target_arch = "x86_64")]
    inv_roots_precon32: AVec<u64>,
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

#[cfg(target_arch = "x86_64")]
/// Build pre-expanded root vectors for AVX2 T2/T1 stages (u64 lanes).
///
/// `inverse` controls traversal direction (see `build_avx2_roots_u32`).
fn build_avx2_roots_u64(n: usize, roots: &[u64], inverse: bool) -> AVec<u64> {
    // n < 16 → scalar fallback, no pre-expanded data needed.
    if n < 16 {
        return AVec::with_capacity(64, 0);
    }
    let mut out = AVec::with_capacity(64, (n / 4) * 4);
    let mut ri = 1usize;
    let (mut t, mut m) = if inverse {
        (1usize, n >> 1)
    } else {
        (n >> 1, 1usize)
    };
    loop {
        if t >= 4 {
            ri += n / (2 * t); // T4: broadcast, skip
        } else {
            match t {
                2 => {
                    for _ in 0..(n / 8) {
                        let w_a = roots[ri];
                        let w_b = roots[ri + 1];
                        ri += 2;
                        out.push(w_a);
                        out.push(w_a);
                        out.push(w_b);
                        out.push(w_b);
                    }
                }
                1 => {
                    for _ in 0..(n / 8) {
                        let w0 = roots[ri];
                        let w1 = roots[ri + 1];
                        let w2 = roots[ri + 2];
                        let w3 = roots[ri + 3];
                        ri += 4;
                        out.push(w3);
                        out.push(w2);
                        out.push(w1);
                        out.push(w0);
                    }
                }
                _ => unreachable!(),
            }
        }
        if inverse {
            t <<= 1;
            m >>= 1;
        } else {
            t >>= 1;
            m <<= 1;
        }
        if inverse {
            if m < 1 {
                break;
            }
        } else if m >= n {
            break;
        }
    }
    out
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
            use super::hexl::{
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

            if matches!(self.backend, U64Backend::Avx2) {
                return unsafe { self.avx2_forward_transform(values, output_mod_factor) };
            }
        }

        self.scalar_forward_transform(values, output_mod_factor);
    }

    /// Dispatch inverse transform to the selected backend.
    ///
    /// Priority: IFMA → DQ → AVX2 → scalar.
    fn dispatch_inverse(&self, values: &mut [u64], output_mod_factor: u32) {
        #[cfg(target_arch = "x86_64")]
        if self.n >= 16 {
            use super::hexl::{
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
                            &self.inv_roots_precon,
                            1,
                            output_mod_factor as u64,
                            0,
                            0,
                        )
                    }
                };
            }

            if matches!(self.backend, U64Backend::Avx2) {
                return unsafe { self.avx2_inverse_transform(values, output_mod_factor) };
            }
        }

        self.scalar_inverse_transform(values, output_mod_factor);
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
        let roots_precon = AVec::from_iter(
            64,
            roots
                .iter()
                .map(|&w| ShoupFactor::<u64>::quotient_for(w, q)),
        );
        let inv_roots_precon = AVec::from_iter(
            64,
            inv_roots
                .iter()
                .map(|&w| ShoupFactor::<u64>::quotient_for(w, q)),
        );

        // --- inv_n = n^{-1} mod q ---
        let inv_n = mod_inv(n as u64, q);
        let inv_n_precon = ShoupFactor::<u64>::quotient_for(inv_n, q);

        // Precompute inv_n_w = inv_n * inv_roots[n-1] mod q for the inverse final stage.
        let last_w = unsafe { *inv_roots.get_unchecked(n - 1) };
        let inv_n_w = scalar::reduce_once(scalar::mul_mod_lazy(last_w, inv_n, inv_n_precon, q), q);
        let inv_n_w_precon = ShoupFactor::<u64>::quotient_for(inv_n_w, q);

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
                build_avx2_roots_u64(n, &roots_precon, false),
                build_avx2_roots_u64(n, &inv_roots, true),
                build_avx2_roots_u64(n, &inv_roots_precon, true),
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
        let (
            avx512_roots,
            avx512_roots_precon32,
            avx512_roots_precon52,
            avx512_roots_precon64,
            inv_roots_precon32,
            inv_roots_precon52,
        ) = if use_avx512 {
            let ar = super::hexl::precompute::build_avx512_root_powers(n, &roots);
            let arp32 = super::hexl::precompute::build_barrett_vector(&ar, 32, q);
            let arp52 = super::hexl::precompute::build_barrett_vector(&ar, 52, q);
            let arp64 = super::hexl::precompute::build_barrett_vector(&ar, 64, q);
            let irp32 = super::hexl::precompute::build_barrett_vector(&inv_roots, 32, q);
            let irp52 = super::hexl::precompute::build_barrett_vector(&inv_roots, 52, q);
            (ar, arp32, arp52, arp64, irp32, irp52)
        } else {
            (
                AVec::with_capacity(64, 0),
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
            root,
            inv_root,
            inv_n,
            inv_n_precon,
            inv_n_w,
            inv_n_w_precon,
            roots,
            roots_precon,
            inv_roots,
            inv_roots_precon,
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
            #[cfg(target_arch = "x86_64")]
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
mod tests {
    use super::*;
    use primus_modulus::BarrettModulus;
    use rand::RngExt;

    const Q: u64 = 132120577;
    const N: usize = 1024;

    fn make_table(log_n: u32, q: u64) -> U64NttTable {
        let modulus = <BarrettModulus<u64>>::new(q);
        U64NttTable::new(log_n, modulus).unwrap()
    }

    /// Check that lazy forward output is in `[0, 4q)`.
    #[test]
    fn test_lazy_forward_range() {
        let table = make_table(10, Q);
        let mut data = vec![0u64; N];

        let mut rng = rand::rng();
        for x in &mut data {
            *x = rng.random_range(0..4 * Q);
        }

        table.lazy_transform_slice(&mut data);

        for &v in &data {
            assert!(v < 4 * Q, "lazy forward output {v} >= 4q");
        }
    }

    /// Check that lazy inverse output is in `[0, 2q)`.
    #[test]
    fn test_lazy_inverse_range() {
        let table = make_table(10, Q);
        let mut data = vec![0u64; N];

        let mut rng = rand::rng();
        for x in &mut data {
            *x = rng.random_range(0..2 * Q);
        }

        table.lazy_inverse_transform_slice(&mut data);

        for &v in &data {
            assert!(v < 2 * Q, "lazy inverse output {v} >= 2q");
        }
    }

    /// Round-trip: forward + inverse restores original.
    #[test]
    fn test_round_trip() {
        let ns = [8u64, 16, 32, 64, 128, 256, 512, 1024];
        let mut rng = rand::rng();

        for &n_val in &ns {
            let log_n = n_val.trailing_zeros();
            let n = 1usize << log_n;

            // Need q ≡ 1 mod 2n for a primitive 2n-th root to exist
            if !(Q - 1).is_multiple_of(2 * n as u64) {
                continue;
            }

            let table = make_table(log_n, Q);

            let mut data: Vec<u64> = (0..n).map(|_| rng.random_range(0..Q)).collect();
            let original = data.clone();

            table.transform_slice(&mut data);
            table.inverse_transform_slice(&mut data);

            assert_eq!(data, original, "round-trip failed for N={n_val}");
        }
    }

    /// Cross-check with `UintNttTable<u64>`.
    #[test]
    fn test_cross_check_against_uint_table() {
        use crate::ntt::UintNttTable;

        let q_mod = <BarrettModulus<u64>>::new(Q);

        let u64_table = make_table(10, Q);
        let uint_table = UintNttTable::<u64>::new(10, q_mod).unwrap();

        let mut rng = rand::rng();

        // Test lazy forward
        {
            let mut data64 = vec![0u64; N];
            let mut data_uint = vec![0u64; N];
            for i in 0..N {
                let v = rng.random_range(0..Q);
                data64[i] = v;
                data_uint[i] = v;
            }
            u64_table.lazy_transform_slice(&mut data64);
            uint_table.lazy_transform_slice(&mut data_uint);

            for i in 0..N {
                assert_eq!(
                    data64[i] % Q,
                    data_uint[i] % Q,
                    "lazy forward mismatch at index {i}"
                );
            }
        }

        // Test canonical forward
        {
            let mut data64 = vec![0u64; N];
            let mut data_uint = vec![0u64; N];
            for i in 0..N {
                let v = rng.random_range(0..Q);
                data64[i] = v;
                data_uint[i] = v;
            }
            u64_table.transform_slice(&mut data64);
            uint_table.transform_slice(&mut data_uint);

            assert_eq!(data64, data_uint, "canonical forward mismatch");
        }

        // Test lazy inverse
        {
            let mut data64 = vec![0u64; N];
            let mut data_uint = vec![0u64; N];
            for i in 0..N {
                let v = rng.random_range(0..Q);
                data64[i] = v;
                data_uint[i] = v;
            }
            u64_table.lazy_inverse_transform_slice(&mut data64);
            uint_table.lazy_inverse_transform_slice(&mut data_uint);

            for i in 0..N {
                assert_eq!(
                    data64[i] % Q,
                    data_uint[i] % Q,
                    "lazy inverse mismatch at index {i}"
                );
            }
        }

        // Test canonical inverse
        {
            let mut data64 = vec![0u64; N];
            let mut data_uint = vec![0u64; N];
            for i in 0..N {
                let v = rng.random_range(0..Q);
                data64[i] = v;
                data_uint[i] = v;
            }
            u64_table.inverse_transform_slice(&mut data64);
            uint_table.inverse_transform_slice(&mut data_uint);

            assert_eq!(data64, data_uint, "canonical inverse mismatch");
        }

        // Test monomial transform
        {
            let coeff = rng.random_range(1..Q);
            let degree = rng.random_range(1..N);
            let mut data64 = vec![0u64; N];
            let mut data_uint = vec![0u64; N];
            u64_table.transform_monomial(coeff, degree, &mut data64);
            uint_table.transform_monomial(coeff, degree, &mut data_uint);

            assert_eq!(
                data64, data_uint,
                "monomial mismatch, coeff={coeff}, degree={degree}"
            );
        }
    }

    /// Cross-check against `UintNttTable` for three modulus sizes that
    /// exercise different Barrett shift widths (32 / 52 / 64).
    #[test]
    fn test_cross_check_barrett_regimes() {
        use crate::ntt::UintNttTable;

        let test_moduli = [536813569u64, 562949953392641, 1152921504606830593];
        let n = 1024;
        let mut rng = rand::rng();

        for &q in &test_moduli {
            let q_mod = <BarrettModulus<u64>>::new(q);
            let u64_table = U64NttTable::new(10, q_mod).unwrap();
            let uint_table = UintNttTable::<u64>::new(10, q_mod).unwrap();

            let mut data64: Vec<u64> = (0..n).map(|_| rng.random_range(0..q)).collect();
            let mut data_uint = data64.clone();

            u64_table.transform_slice(&mut data64);
            uint_table.transform_slice(&mut data_uint);
            assert_eq!(data64, data_uint, "forward mismatch for q={q}");

            u64_table.inverse_transform_slice(&mut data64);
            uint_table.inverse_transform_slice(&mut data_uint);
            assert_eq!(data64, data_uint, "inverse mismatch for q={q}");
        }
    }

    /// Round-trip + cross-check with `UintNttTable<u64>` for large moduli.
    #[test]
    fn test_large_modulus_round_trip() {
        use crate::ntt::UintNttTable;

        let test_moduli = [562949953392641u64, 1152921504606830593];
        let n = 1024;
        let mut rng = rand::rng();

        for &q in &test_moduli {
            let q_mod = <BarrettModulus<u64>>::new(q);
            let u64_table = U64NttTable::new(10, q_mod).unwrap();
            let uint_table = UintNttTable::<u64>::new(10, q_mod).unwrap();

            // Round-trip
            let mut data: Vec<u64> = (0..n).map(|_| rng.random_range(0..q)).collect();
            let original = data.clone();
            u64_table.transform_slice(&mut data);
            u64_table.inverse_transform_slice(&mut data);
            assert_eq!(data, original, "round-trip failed for q={q}");

            // Cross-check forward
            let mut data_u64: Vec<u64> = (0..n).map(|_| rng.random_range(0..q)).collect();
            let mut data_uint = data_u64.clone();
            u64_table.transform_slice(&mut data_u64);
            uint_table.transform_slice(&mut data_uint);
            assert_eq!(data_u64, data_uint, "forward mismatch vs uint for q={q}");

            // Cross-check inverse
            u64_table.inverse_transform_slice(&mut data_u64);
            uint_table.inverse_transform_slice(&mut data_uint);
            assert_eq!(data_u64, data_uint, "inverse mismatch vs uint for q={q}");
        }
    }
}
