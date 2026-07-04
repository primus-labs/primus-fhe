use aligned_vec::{AVec, avec};
use primus_data::{DataMut, RawData};
use primus_factor::{FactorBase, FactorMul, LazyFactorMul, ShoupFactor};
use primus_gcd::Xgcd;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

use crate::{NttError, ntt::NttTable, reverse::ReverseLsbs, root::PrimitiveRoot};

#[cfg(target_arch = "x86_64")]
use super::avx2;
use super::scalar;

/// Backend selector for `U64NttTable`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum U64Backend {
    Scalar,
    /// AVX2 backend — available on x86_64 with `avx2` target feature.
    #[cfg(target_arch = "x86_64")]
    Avx2,
}

/// Specialized NTT table for `u64` coefficients.
///
/// Stores roots and Barrett-64 preconditioners in structure-of-arrays layout
/// for fast scalar (and future SIMD) access.
///
/// # Constraints
///
/// - `q < 2^62` — ensures lazy ranges `[0, 4q)` fit in `u64`.
pub struct U64NttTable {
    n: usize,
    log_n: u32,
    q: u64,
    two_q: u64,
    root: u64,
    inv_root: u64,

    inv_n: u64,
    inv_n_precon: u64,
    /// `inv_n * inv_roots[n-1] mod q` — precomputed for the inverse final stage.
    inv_n_w: u64,
    /// Shoup preconditioner for `inv_n_w`.
    inv_n_w_precon: u64,

    /// Forward roots in bit-reversed order (size `n`).
    roots: AVec<u64>,
    /// Barrett-64 preconditioners for `roots` (size `n`).
    roots_precon: AVec<u64>,
    /// Inverse roots in bit-reversed order (size `n`).
    inv_roots: AVec<u64>,
    /// Barrett-64 preconditioners for `inv_roots` (size `n`).
    inv_roots_precon: AVec<u64>,

    /// Ordinal powers: `[1, w, w^2, ..., w^(2n-1)]` (size `2n`).
    ordinal_roots: Vec<u64>,
    /// Bit-reversed index mapping (size `n`).
    reverse_lsbs: Vec<usize>,

    #[allow(dead_code)]
    backend: U64Backend,
}

/// Modular multiplication: `(a * b) mod q`.
///
/// Uses `ShoupFactor` for reduction. For repeated multiplication by the
/// same value, precompute the `ShoupFactor` outside the loop (see
/// `transform_monomial`).
#[inline]
fn mul_mod(a: u64, b: u64, q: u64) -> u64 {
    ShoupFactor::<u64>::new(b, q).factor_mul_modulo(a, q)
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
    fn dispatch_forward(&self, values: &mut [u64], input_mod_factor: u32, output_mod_factor: u32) {
        match self.backend {
            U64Backend::Scalar => scalar::forward_transform(
                values,
                self.q,
                self.two_q,
                &self.roots,
                &self.roots_precon,
                input_mod_factor,
                output_mod_factor,
            ),
            #[cfg(target_arch = "x86_64")]
            U64Backend::Avx2 => {
                // SAFETY: Avx2 backend is only selected when
                // avx2::HAS_AVX2 is true at construction time.
                unsafe {
                    avx2::forward_transform(
                        values,
                        self.q,
                        self.two_q,
                        &self.roots,
                        &self.roots_precon,
                        input_mod_factor,
                        output_mod_factor,
                    )
                }
            }
        }
    }

    /// Dispatch inverse transform to the selected backend.
    fn dispatch_inverse(&self, values: &mut [u64], input_mod_factor: u32, output_mod_factor: u32) {
        match self.backend {
            U64Backend::Scalar => scalar::inverse_transform(
                values,
                self.q,
                self.two_q,
                self.inv_n,
                self.inv_n_precon,
                self.inv_n_w,
                self.inv_n_w_precon,
                &self.inv_roots,
                &self.inv_roots_precon,
                input_mod_factor,
                output_mod_factor,
            ),
            #[cfg(target_arch = "x86_64")]
            U64Backend::Avx2 => unsafe {
                avx2::inverse_transform(
                    values,
                    self.q,
                    self.two_q,
                    self.inv_n,
                    self.inv_n_precon,
                    self.inv_n_w,
                    self.inv_n_w_precon,
                    &self.inv_roots,
                    &self.inv_roots_precon,
                    input_mod_factor,
                    output_mod_factor,
                )
            },
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

        // --- ordinal roots: [1, w, w^2, ..., w^(2n-1)] ---
        let root_sf = ShoupFactor::<u64>::new(root, q);
        let mut ordinal_roots = vec![0u64; n * 2];
        ordinal_roots[0] = 1;
        ordinal_roots[1] = root;
        let mut power = root;
        for dst in &mut ordinal_roots[2..] {
            power = root_sf.lazy_factor_mul_modulo(power, q);
            power = scalar::reduce_once(power, q); // keep canonical for iteration
            *dst = power;
        }

        let inv_root = *ordinal_roots.last().unwrap();
        debug_assert_eq!(mul_mod(root, inv_root, q), 1);

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
            backend: if *avx2::HAS_AVX2 {
                U64Backend::Avx2
            } else {
                U64Backend::Scalar
            },
            #[cfg(not(target_arch = "x86_64"))]
            backend: U64Backend::Scalar,
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

    fn lazy_transform_slice(&self, poly: &mut [u64]) {
        debug_assert_eq!(poly.len(), self.n);
        self.dispatch_forward(poly, 4, 4);
    }

    fn transform_slice(&self, poly: &mut [u64]) {
        debug_assert_eq!(poly.len(), self.n);
        self.dispatch_forward(poly, 4, 1);
    }

    fn lazy_inverse_transform_slice(&self, values: &mut [u64]) {
        debug_assert_eq!(values.len(), self.n);
        self.dispatch_inverse(values, 2, 2);
    }

    fn inverse_transform_slice(&self, values: &mut [u64]) {
        debug_assert_eq!(values.len(), self.n);
        self.dispatch_inverse(values, 2, 1);
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

    /// Cross-check with `HexlNttTable` for all three Barrett regimes.
    #[test]
    fn test_cross_check_against_hexl() {
        use crate::ntt::HexlNttTable;

        let test_moduli = [536813569u64, 562949953392641, 1152921504606830593];
        let n = 1024;
        let mut rng = rand::rng();

        for &q in &test_moduli {
            // Skip if 2n doesn't divide q-1
            let q_mod = <BarrettModulus<u64>>::new(q);
            let u64_table = U64NttTable::new(10, q_mod).unwrap();
            let hexl_table = HexlNttTable::new(10, q_mod).unwrap();

            let mut data64: Vec<u64> = (0..n).map(|_| rng.random_range(0..q)).collect();
            let mut data_hexl = data64.clone();

            u64_table.transform_slice(&mut data64);
            hexl_table.transform_slice(&mut data_hexl);
            assert_eq!(data64, data_hexl, "forward mismatch vs hexl for q={q}");

            u64_table.inverse_transform_slice(&mut data64);
            hexl_table.inverse_transform_slice(&mut data_hexl);
            assert_eq!(
                data64, data_hexl,
                "round-trip via inverse mismatch vs hexl for q={q}"
            );
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
