use aligned_vec::{AVec, avec};
use primus_data::{DataMut, RawData};
use primus_factor::{FactorBase, FactorMul, ShoupFactor};
use primus_gcd::Xgcd;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

#[cfg(target_arch = "x86_64")]
use crate::constants::{HAS_AVX2, HAS_AVX512F};
use crate::{NttError, ntt::NttTable, reverse::ReverseLsbs, root::PrimitiveRoot};

use super::scalar;
#[cfg(target_arch = "x86_64")]
use super::{avx2::precompute::build_avx2_roots_u32, avx512::precompute::build_avx512_roots_u32};

/// Backend selector for `U32NttTable`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum U32Backend {
    Scalar,
    /// AVX2 backend — available on x86_64 with `avx2` target feature.
    #[cfg(target_arch = "x86_64")]
    Avx2,
    /// AVX-512 backend — available on x86_64 with `avx512f` target feature.
    #[cfg(target_arch = "x86_64")]
    Avx512,
}

/// Specialized NTT table for `u32` coefficients.
///
/// Stores roots and Barrett-32 preconditioners in structure-of-arrays layout
/// for fast scalar (and future SIMD) access.
///
/// # Constraints
///
/// - `q < 2^30` — ensures lazy ranges `[0, 4q)` fit in `u32`.
#[derive(Clone)]
pub struct U32NttTable {
    pub(super) n: usize,
    pub(super) log_n: u32,
    pub(super) q: u32,
    pub(super) two_q: u32,
    pub(super) root: u32,
    pub(super) inv_root: u32,
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

    /// Ordinal powers: `[1, w, w^2, ..., w^(2n-1)]` (size `2n`).
    ordinal_roots: Vec<u32>,
    /// Bit-reversed index mapping (size `n`).
    reverse_lsbs: Vec<usize>,

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

    backend: U32Backend,
}

/// Compute the modular inverse of `a` modulo `q`.
///
/// Uses `primus_gcd::Xgcd::gcdinv` — an optimized binary GCD
/// that avoids division instructions.
fn mod_inv(a: u32, q: u32) -> u32 {
    debug_assert!(a < q);
    let (inv, gcd) = u32::gcdinv(a, q);
    assert_eq!(gcd, 1, "a={a} is not invertible modulo q={q}");
    inv
}

impl U32NttTable {
    /// Returns the modulus `q`.
    #[inline]
    pub fn modulus(&self) -> u32 {
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
    pub fn root(&self) -> u32 {
        self.root
    }

    /// Returns the inverse of the primitive root.
    #[inline]
    pub fn inv_root(&self) -> u32 {
        self.inv_root
    }

    /// Returns the inverse of `N` modulo `q`.
    #[inline]
    pub fn inv_n(&self) -> u32 {
        self.inv_n
    }

    /// Dispatch forward transform to the selected backend.
    ///
    /// SIMD paths require `n ≥ 32`; smaller transforms go directly to scalar.
    #[inline]
    fn dispatch_forward(&self, values: &mut [u32], output_mod_factor: u32) {
        if self.n >= 32 {
            match self.backend {
                #[cfg(target_arch = "x86_64")]
                U32Backend::Avx2 => unsafe {
                    return self.avx2_forward_transform(values, output_mod_factor);
                },
                #[cfg(target_arch = "x86_64")]
                U32Backend::Avx512 => unsafe {
                    return self.avx512_forward_transform(values, output_mod_factor);
                },
                U32Backend::Scalar => {}
            }
        }
        self.scalar_forward_transform(values, output_mod_factor);
    }

    /// Dispatch inverse transform to the selected backend.
    #[inline]
    fn dispatch_inverse(&self, values: &mut [u32], output_mod_factor: u32) {
        if self.n >= 32 {
            match self.backend {
                #[cfg(target_arch = "x86_64")]
                U32Backend::Avx2 => unsafe {
                    return self.avx2_inverse_transform(values, output_mod_factor);
                },
                #[cfg(target_arch = "x86_64")]
                U32Backend::Avx512 => unsafe {
                    return self.avx512_inverse_transform(values, output_mod_factor);
                },
                U32Backend::Scalar => {}
            }
        }
        self.scalar_inverse_transform(values, output_mod_factor);
    }
}

impl NttTable for U32NttTable {
    type ValueT = u32;

    fn new<M>(log_n: u32, modulus: M) -> Result<Self, NttError<Self::ValueT>>
    where
        M: FieldContext<Self::ValueT>,
    {
        let root = <u32 as PrimitiveRoot>::try_minimal_primitive_root(log_n + 1, modulus)?;
        let Some(q) = modulus.value() else {
            return Err(NttError::NttTableErr);
        };

        // Reject unsupported moduli: q < 2^30 required for lazy [0, 4q) range.
        if q >= 1 << 30 {
            return Err(NttError::ModulusTooLarge {
                modulus: q,
                max_bits: 30,
            });
        }

        let n = 1usize << log_n;
        let two_q = q << 1;

        // --- ordinal roots: [1, w, w^2, ..., w^(2n-1)] ---
        let root_sf = ShoupFactor::<u32>::new(root, q);
        let mut ordinal_roots = vec![0u32; n * 2];
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
        let mut roots = avec![0u32; n];
        roots[0] = 1;
        for (&rp, &i) in ordinal_roots[0..n].iter().zip(reverse_lsbs.iter()) {
            roots[i] = rp;
        }

        // --- inverse roots (bit-reversed, scrambled order) ---
        let mut inv_roots = avec![0u32; n];
        inv_roots[0] = 1;
        for (&irp, &i) in ordinal_roots[n + 1..].iter().rev().zip(reverse_lsbs.iter()) {
            inv_roots[i + 1] = irp;
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
        let backend = if *HAS_AVX512F {
            U32Backend::Avx512
        } else if *HAS_AVX2 {
            U32Backend::Avx2
        } else {
            U32Backend::Scalar
        };
        #[cfg(not(target_arch = "x86_64"))]
        let backend = U32Backend::Scalar;

        // --- backend-specific pre-expanded root tables ---
        // Only build for the selected backend to save memory and init time.
        #[cfg(target_arch = "x86_64")]
        let use_avx2 = matches!(backend, U32Backend::Avx2 | U32Backend::Avx512);
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
            avx512_roots_precon,
            #[cfg(target_arch = "x86_64")]
            avx512_inv_roots,
            #[cfg(target_arch = "x86_64")]
            avx512_inv_roots_precon,
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

    fn lazy_transform_slice(&self, poly: &mut [u32]) {
        debug_assert_eq!(poly.len(), self.n);
        self.dispatch_forward(poly, 4);
    }

    fn transform_slice(&self, poly: &mut [u32]) {
        debug_assert_eq!(poly.len(), self.n);
        self.dispatch_forward(poly, 1);
    }

    fn lazy_inverse_transform_slice(&self, values: &mut [u32]) {
        debug_assert_eq!(values.len(), self.n);
        self.dispatch_inverse(values, 2);
    }

    fn inverse_transform_slice(&self, values: &mut [u32]) {
        debug_assert_eq!(values.len(), self.n);
        self.dispatch_inverse(values, 1);
    }

    fn transform_monomial(&self, coeff: u32, degree: usize, values: &mut [u32]) {
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
            let coeff_sf = ShoupFactor::<u32>::new(coeff, self.q);
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

    fn transform_coeff_one_monomial(&self, degree: usize, values: &mut [u32]) {
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

    fn transform_coeff_minus_one_monomial(&self, degree: usize, values: &mut [u32]) {
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
