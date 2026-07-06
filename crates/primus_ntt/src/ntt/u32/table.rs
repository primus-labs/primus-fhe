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

#[cfg(target_arch = "x86_64")]
/// Build pre-expanded root vectors for AVX2 T4/T2 stages.
///
/// `inverse` controls traversal direction:
/// - `false` (forward): t decreases from `n/2` down to 1.
/// - `true`  (inverse): t increases from 1 up to `n/2`.
fn build_avx2_roots_u32(n: usize, roots: &[u32], inverse: bool) -> AVec<u32> {
    // n < 32 → scalar fallback, no pre-expanded data needed.
    if n < 32 {
        return AVec::with_capacity(32, 0);
    }
    let mut out = AVec::with_capacity(32, (n / 8) * 8);
    let mut ri = 1usize;
    let (mut t, mut m) = if inverse {
        (1usize, n >> 1)
    } else {
        (n >> 1, 1usize)
    };
    loop {
        if t >= 8 {
            ri += n / (2 * t); // T8: broadcast, skip
        } else {
            match t {
                4 => {
                    for _ in 0..(n / 16) {
                        let w0 = roots[ri];
                        let w1 = roots[ri + 1];
                        ri += 2;
                        for _ in 0..4 {
                            out.push(w0);
                        }
                        for _ in 0..4 {
                            out.push(w1);
                        }
                    }
                }
                2 => {
                    for _ in 0..(n / 16) {
                        let w0 = roots[ri];
                        let w1 = roots[ri + 1];
                        let w2 = roots[ri + 2];
                        let w3 = roots[ri + 3];
                        ri += 4;
                        out.push(w0);
                        out.push(w0);
                        out.push(w2);
                        out.push(w2);
                        out.push(w1);
                        out.push(w1);
                        out.push(w3);
                        out.push(w3);
                    }
                }
                1 => {
                    // T1: already uses _mm256_loadu_si256 from scalar roots
                    ri += n / 2;
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

#[cfg(target_arch = "x86_64")]
/// Build pre-expanded root vectors for AVX-512 T8/T4/T2/T1 stages.
///
/// `inverse` controls traversal direction (see `build_avx2_roots_u32`).
fn build_avx512_roots_u32(n: usize, roots: &[u32], inverse: bool) -> AVec<u32> {
    // n < 64 → scalar fallback, no pre-expanded data needed.
    if n < 64 {
        return AVec::with_capacity(64, 0);
    }
    let mut out = AVec::with_capacity(64, (n / 8) * 16);
    let mut ri = 1usize;
    let (mut t, mut m) = if inverse {
        (1usize, n >> 1)
    } else {
        (n >> 1, 1usize)
    };
    loop {
        if t >= 16 {
            ri += n / (2 * t); // T16: broadcast, skip
        } else if t == 8 {
            for _ in 0..(n / 32) {
                let w0 = roots[ri];
                let w1 = roots[ri + 1];
                ri += 2;
                for _ in 0..8 {
                    out.push(w0);
                }
                for _ in 0..8 {
                    out.push(w1);
                }
            }
        } else {
            let num_w = 16 / t;
            for _ in 0..(n / 32) {
                for j in 0..num_w {
                    let w = roots[ri + j];
                    for _ in 0..t {
                        out.push(w);
                    }
                }
                ri += num_w;
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
mod tests {
    use super::*;
    use primus_modulus::BarrettModulus;
    use rand::RngExt;

    const Q: u32 = 132120577; // 27-bit prime, 1 mod 2048
    const N: usize = 1024;

    fn make_table(log_n: u32, q: u32) -> U32NttTable {
        let modulus = <BarrettModulus<u32>>::new(q);
        U32NttTable::new(log_n, modulus).unwrap()
    }

    /// Check that lazy forward output is in `[0, 4q)`.
    #[test]
    fn test_lazy_forward_range() {
        let table = make_table(10, Q);
        let mut data = vec![0u32; N];

        let mut rng = rand::rng();
        for x in &mut data {
            *x = rng.random_range(0..4 * Q);
        }

        let original = data.clone();
        table.lazy_transform_slice(&mut data);

        for &v in &data {
            assert!(v < 4 * Q, "lazy forward output {v} >= 4q");
        }
        assert_ne!(data, original);
    }

    /// Check that lazy inverse output is in `[0, 2q)`.
    #[test]
    fn test_lazy_inverse_range() {
        let table = make_table(10, Q);
        let mut data = vec![0u32; N];

        let mut rng = rand::rng();
        for x in &mut data {
            *x = rng.random_range(0..2 * Q);
        }

        table.lazy_inverse_transform_slice(&mut data);

        for &v in &data {
            assert!(v < 2 * Q, "lazy inverse output {v} >= 2q");
        }
    }

    /// Check canonical forward output is in `[0, q)`.
    #[test]
    fn test_canonical_forward_range() {
        let table = make_table(10, Q);
        let mut data = vec![0u32; N];

        let mut rng = rand::rng();
        for x in &mut data {
            *x = rng.random_range(0..Q);
        }

        table.transform_slice(&mut data);

        for &v in &data {
            assert!(v < Q, "canonical forward output {v} >= q");
        }
    }

    /// Check canonical inverse output is in `[0, q)`.
    #[test]
    fn test_canonical_inverse_range() {
        let table = make_table(10, Q);
        let mut data = vec![0u32; N];

        let mut rng = rand::rng();
        for x in &mut data {
            *x = rng.random_range(0..Q);
        }

        table.inverse_transform_slice(&mut data);

        for &v in &data {
            assert!(v < Q, "canonical inverse output {v} >= q");
        }
    }

    /// Cross-path: `[0, 4q)` input via `lazy_transform_slice` + reduce
    /// matches `[0, q)` input via `transform_slice` modulo `q`.
    #[test]
    fn test_lazy_vs_canonical_forward() {
        let table = make_table(10, Q);
        let mut rng = rand::rng();

        let mut lazy_in: Vec<u32> = (0..N).map(|_| rng.random_range(0..4 * Q)).collect();
        let mut canonical_in: Vec<u32> = lazy_in.iter().map(|&x| x % Q).collect();

        table.lazy_transform_slice(&mut lazy_in);
        table.transform_slice(&mut canonical_in);

        for i in 0..N {
            assert_eq!(
                lazy_in[i] % Q,
                canonical_in[i],
                "lazy vs canonical forward mismatch at index {i}"
            );
        }
    }

    /// Round-trip: forward + inverse restores original.
    #[test]
    fn test_round_trip() {
        let ns = [8u32, 16, 32, 64, 128, 256, 512, 1024];
        let mut rng = rand::rng();

        for &n_val in &ns {
            let log_n = n_val.trailing_zeros();
            let n = 1usize << log_n;

            // Need q ≡ 1 mod 2n for a primitive 2n-th root to exist
            if !(Q as u64 - 1).is_multiple_of(2 * n as u64) {
                continue;
            }

            let table = make_table(log_n, Q);

            let mut data: Vec<u32> = (0..n).map(|_| rng.random_range(0..Q)).collect();
            let original = data.clone();

            table.transform_slice(&mut data);
            table.inverse_transform_slice(&mut data);

            assert_eq!(data, original, "round-trip failed for N={n_val}");
        }
    }

    /// Cross-check with `UintNttTable<u32>`.
    #[test]
    fn test_cross_check_against_uint_table() {
        use crate::ntt::UintNttTable;

        let q_mod = <BarrettModulus<u32>>::new(Q);

        let u32_table = make_table(10, Q);
        let uint_table = UintNttTable::<u32>::new(10, q_mod).unwrap();

        let mut rng = rand::rng();

        // Test lazy forward
        {
            let mut data32 = vec![0u32; N];
            let mut data_uint = vec![0u32; N];
            for i in 0..N {
                let v = rng.random_range(0..Q);
                data32[i] = v;
                data_uint[i] = v;
            }
            u32_table.lazy_transform_slice(&mut data32);
            uint_table.lazy_transform_slice(&mut data_uint);

            for i in 0..N {
                assert_eq!(
                    data32[i] % Q,
                    data_uint[i] % Q,
                    "lazy forward mismatch at index {i}"
                );
            }
        }

        // Test canonical forward
        {
            let mut data32 = vec![0u32; N];
            let mut data_uint = vec![0u32; N];
            for i in 0..N {
                let v = rng.random_range(0..Q);
                data32[i] = v;
                data_uint[i] = v;
            }
            u32_table.transform_slice(&mut data32);
            uint_table.transform_slice(&mut data_uint);

            assert_eq!(data32, data_uint, "canonical forward mismatch");
        }

        // Test lazy inverse
        {
            let mut data32 = vec![0u32; N];
            let mut data_uint = vec![0u32; N];
            for i in 0..N {
                let v = rng.random_range(0..Q);
                data32[i] = v;
                data_uint[i] = v;
            }
            u32_table.lazy_inverse_transform_slice(&mut data32);
            uint_table.lazy_inverse_transform_slice(&mut data_uint);

            for i in 0..N {
                assert_eq!(
                    data32[i] % Q,
                    data_uint[i] % Q,
                    "lazy inverse mismatch at index {i}"
                );
            }
        }

        // Test canonical inverse
        {
            let mut data32 = vec![0u32; N];
            let mut data_uint = vec![0u32; N];
            for i in 0..N {
                let v = rng.random_range(0..Q);
                data32[i] = v;
                data_uint[i] = v;
            }
            u32_table.inverse_transform_slice(&mut data32);
            uint_table.inverse_transform_slice(&mut data_uint);

            assert_eq!(data32, data_uint, "canonical inverse mismatch");
        }

        // Test monomial transform
        {
            let coeff = rng.random_range(1..Q);
            let degree = rng.random_range(1..N);
            let mut data32 = vec![0u32; N];
            let mut data_uint = vec![0u32; N];
            u32_table.transform_monomial(coeff, degree, &mut data32);
            uint_table.transform_monomial(coeff, degree, &mut data_uint);

            assert_eq!(
                data32, data_uint,
                "monomial mismatch, coeff={coeff}, degree={degree}"
            );
        }
    }

    /// Verify pre-expanded root layout matches the old lane patterns
    /// (tests the builder directly, no SIMD hardware needed).
    #[test]
    fn test_builder_lane_order() {
        // Use a small N=64 and a known identity-like root pattern.
        // Each root = its bit-reversed index, modulo a dummy q.
        let n = 64;
        // dummy roots: roots[i] = i (for forward), inv_roots[i] = i + 100 (for inverse)
        let roots: Vec<u32> = (0..n).map(|i| i as u32).collect();
        let inv_roots: Vec<u32> = (0..n).map(|i| (i + 100) as u32).collect();

        // Build AVX2 forward/inverse
        let avx2_fwd = super::build_avx2_roots_u32(n, &roots, false);
        let avx2_inv = super::build_avx2_roots_u32(n, &inv_roots, true);

        // Basic sanity: non-empty and aligned
        assert!(
            !avx2_fwd.is_empty(),
            "avx2 forward roots should be non-empty for n=64"
        );
        assert!(
            avx2_fwd.len() % 8 == 0,
            "avx2 output must be multiple of 8 u32s"
        );

        // For n=64, the forward traversal:
        // T8 (t=32,16,8): ri goes from 1 to 8 (consumes roots[1..8])
        // T4 (t=4): ri starts at 8, n/16=4 chunks. Chunk 0: [roots[8]×4, roots[9]×4]
        assert_eq!(avx2_fwd[0], roots[8]);
        assert_eq!(avx2_fwd[4], roots[9]);

        // T2: after T4 (4 vectors × 8 u32 = 32 u32s), ri at 16.
        // Chunk 0: [roots[16],roots[16], roots[18],roots[18], roots[17],roots[17], roots[19],roots[19]]
        let t2_off = 4 * 8; // 4 T4 vectors × 8 u32 each
        assert_eq!(avx2_fwd[t2_off], roots[16]);
        assert_eq!(avx2_fwd[t2_off + 1], roots[16]); // w0 dup
        assert_eq!(avx2_fwd[t2_off + 2], roots[18]); // w2 → lanes 3,2
        assert_eq!(avx2_fwd[t2_off + 3], roots[18]);
        assert_eq!(avx2_fwd[t2_off + 4], roots[17]); // w1 → lanes 5,4
        assert_eq!(avx2_fwd[t2_off + 5], roots[17]);
        assert_eq!(avx2_fwd[t2_off + 6], roots[19]); // w3 → lanes 7,6
        assert_eq!(avx2_fwd[t2_off + 7], roots[19]);

        // AVX2 inverse: T1 skipped (ri += n/2=32), T2 at ri=33.
        // Chunk 0: [inv_roots[33]×2, inv_roots[35]×2, inv_roots[34]×2, inv_roots[36]×2]
        assert_eq!(avx2_inv[0], inv_roots[33]);
        assert_eq!(avx2_inv[2], inv_roots[35]);
        assert_eq!(avx2_inv[4], inv_roots[34]);
        assert_eq!(avx2_inv[6], inv_roots[36]);
        assert_eq!(avx2_inv.len(), 64); // T2: 4 vec + T4: 4 vec × 8 u32 = 64 u32

        // AVX512 forward: T16 (t=32,16) skip, ri=4. T8 at ri=4, 2 chunks.
        // Chunk 0: [roots[4]×8, roots[5]×8]
        let avx512_fwd = super::build_avx512_roots_u32(n, &roots, false);
        assert!(!avx512_fwd.is_empty());
        assert!(avx512_fwd.len() % 16 == 0);
        assert_eq!(avx512_fwd[0], roots[4]);
        assert_eq!(avx512_fwd[8], roots[5]);
    }
}
