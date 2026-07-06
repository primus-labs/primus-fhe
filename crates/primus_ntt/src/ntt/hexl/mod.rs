use aligned_vec::AVec;
use primus_data::{DataMut, RawData};
use primus_factor::MultiplyFactor;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

use crate::{
    NttError, NttTable, PrimitiveRoot,
    ntt::hexl::{
        internal::*,
        precompute::{
            build_avx512_root_powers, build_barrett_vector, build_ordinal_powers, build_root_powers,
        },
    },
};

mod butterfly;
mod dispatch;
pub(crate) mod internal;
mod number_theory;
pub(crate) mod precompute;
pub(crate) mod scalar;
mod stages;
pub(crate) mod transform;
pub(crate) mod utils;

pub use utils::CmpInt;

/// Re-export from `crate::ntt::constants` so `dispatch` and module body
/// code keep working without path changes.
pub(super) use crate::constants::{HAS_AVX512DQ, HAS_AVX512IFMA};

/// Performs negacyclic forward and inverse number-theoretic transforms (NTT),
/// commonly used in RLWE cryptography.
///
/// The number-theoretic transform (NTT) specializes the discrete Fourier
/// transform (DFT) to the finite field `Z_q[X] / (X^N + 1)`.
pub struct HexlNttTable {
    /// size of NTT transform, should be power of 2
    n: usize,
    /// prime modulus. Must satisfy q == 1 mod 2n
    q: u64,
    /// log_2(n)
    log_n: u32,
    inv_n: u64,
    /// A 2N'th root of unity
    root: u64,
    /// Inverse of minimal root of unity
    inv_root: u64,
    /// powers of the minimal root of unity
    root_of_unity_powers: AVec<u64>,
    /// vector of floor(W * 2**32 / q), with W the root of unity powers
    precon32_root_of_unity_powers: AVec<u64>,
    /// vector of floor(W * 2**64 / q), with W the root of unity powers
    precon64_root_of_unity_powers: AVec<u64>,

    /// powers of the minimal root of unity adjusted for use in AVX512
    avx512_root_of_unity_powers: AVec<u64>,
    /// vector of floor(W * 2**32 / q), with W the AVX512 root of unity powers
    avx512_precon32_root_of_unity_powers: AVec<u64>,
    /// vector of floor(W * 2**52 / q), with W the AVX512 root of unity powers
    avx512_precon52_root_of_unity_powers: AVec<u64>,
    /// vector of floor(W * 2**64 / q), with W the AVX512 root of unity powers
    avx512_precon64_root_of_unity_powers: AVec<u64>,

    /// vector of floor(W * 2**32 / q), with W the inverse root of unity powers
    precon32_inv_root_of_unity_powers: AVec<u64>,
    /// vector of floor(W * 2**52 / q), with W the inverse root of unity powers
    precon52_inv_root_of_unity_powers: AVec<u64>,
    /// vector of floor(W * 2**64 / q), with W the inverse root of unity powers
    precon64_inv_root_of_unity_powers: AVec<u64>,

    inv_root_of_unity_powers: AVec<u64>,

    ordinal_root_powers: Vec<u64>,
    reverse_lsbs: Vec<usize>,
}

impl HexlNttTable {
    pub fn n(&self) -> usize {
        self.n
    }

    pub fn q(&self) -> u64 {
        self.q
    }

    pub fn log_n(&self) -> u32 {
        self.log_n
    }

    pub fn root(&self) -> u64 {
        self.root
    }

    pub fn inv_root(&self) -> u64 {
        self.inv_root
    }

    pub fn root_of_unity_powers(&self) -> &[u64] {
        &self.root_of_unity_powers
    }

    pub fn precon32_root_of_unity_powers(&self) -> &[u64] {
        &self.precon32_root_of_unity_powers
    }

    pub fn precon64_root_of_unity_powers(&self) -> &[u64] {
        &self.precon64_root_of_unity_powers
    }

    pub fn avx512_root_of_unity_powers(&self) -> &[u64] {
        &self.avx512_root_of_unity_powers
    }

    pub fn avx512_precon32_root_of_unity_powers(&self) -> &[u64] {
        &self.avx512_precon32_root_of_unity_powers
    }

    pub fn avx512_precon52_root_of_unity_powers(&self) -> &[u64] {
        &self.avx512_precon52_root_of_unity_powers
    }

    pub fn avx512_precon64_root_of_unity_powers(&self) -> &[u64] {
        &self.avx512_precon64_root_of_unity_powers
    }

    pub fn precon32_inv_root_of_unity_powers(&self) -> &[u64] {
        &self.precon32_inv_root_of_unity_powers
    }

    pub fn precon52_inv_root_of_unity_powers(&self) -> &[u64] {
        &self.precon52_inv_root_of_unity_powers
    }

    pub fn precon64_inv_root_of_unity_powers(&self) -> &[u64] {
        &self.precon64_inv_root_of_unity_powers
    }

    pub fn inv_root_of_unity_powers(&self) -> &[u64] {
        &self.inv_root_of_unity_powers
    }
}

impl NttTable for HexlNttTable {
    type ValueT = u64;

    /// Initializes an NTT object with degree `2^log_n` and modulus `q`.
    ///
    /// ## Parameters
    /// - `log_n`: Also known as log(n) where n is size of the NTT transform.
    /// - `q`: Prime modulus. Must satisfy `q ≡ 1 (mod 2n)`.
    ///
    /// Performs pre-computation necessary for forward and inverse transforms.
    fn new<M>(log_n: u32, modulus: M) -> Result<Self, NttError<Self::ValueT>>
    where
        M: FieldContext<Self::ValueT>,
    {
        let q = unsafe { modulus.value_unchecked() };
        let n = 1usize << log_n;
        check_arguments(n, q);

        let root = <u64 as PrimitiveRoot>::try_minimal_primitive_root(log_n + 1, modulus)?;

        let (ordinal_root_powers, inv_root) = build_ordinal_powers(root, q, n);

        let (root_of_unity_powers, inv_root_of_unity_powers, reverse_lsbs) =
            build_root_powers(n, log_n, &ordinal_root_powers);

        let avx512_root_of_unity_powers = build_avx512_root_powers(n, &root_of_unity_powers);

        // Scalar Barrett vectors
        let precon32_root_of_unity_powers = build_barrett_vector(&root_of_unity_powers, 32, q);
        let precon64_root_of_unity_powers = build_barrett_vector(&root_of_unity_powers, 64, q);

        let precon32_inv_root_of_unity_powers =
            build_barrett_vector(&inv_root_of_unity_powers, 32, q);
        let precon64_inv_root_of_unity_powers =
            build_barrett_vector(&inv_root_of_unity_powers, 64, q);

        // AVX512 IFMA Barrett vectors (52-bit)
        let avx512_precon52_root_of_unity_powers = if *HAS_AVX512IFMA {
            build_barrett_vector(&avx512_root_of_unity_powers, 52, q)
        } else {
            AVec::new(0)
        };

        let precon52_inv_root_of_unity_powers = if *HAS_AVX512IFMA {
            build_barrett_vector(&inv_root_of_unity_powers, 52, q)
        } else {
            AVec::new(0)
        };

        // AVX512 DQ Barrett vectors (32/64-bit)
        let (avx512_precon32_root_of_unity_powers, avx512_precon64_root_of_unity_powers) =
            if *HAS_AVX512DQ {
                (
                    build_barrett_vector(&avx512_root_of_unity_powers, 32, q),
                    build_barrett_vector(&avx512_root_of_unity_powers, 64, q),
                )
            } else {
                (AVec::new(0), AVec::new(0))
            };

        let inv_n = modulus.reduce_inv(n as u64);

        Ok(Self {
            n,
            q,
            log_n,
            inv_n,
            root,
            inv_root,
            root_of_unity_powers,
            precon32_root_of_unity_powers,
            precon64_root_of_unity_powers,
            avx512_root_of_unity_powers,
            avx512_precon32_root_of_unity_powers,
            avx512_precon52_root_of_unity_powers,
            avx512_precon64_root_of_unity_powers,
            precon32_inv_root_of_unity_powers,
            precon52_inv_root_of_unity_powers,
            precon64_inv_root_of_unity_powers,
            inv_root_of_unity_powers,
            ordinal_root_powers,
            reverse_lsbs,
        })
    }

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
    fn lazy_transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]) {
        self.compute_forward(poly, 1, 4);
    }

    #[inline]
    fn transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]) {
        self.compute_forward(poly, 1, 1);
    }

    #[inline]
    fn lazy_inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]) {
        self.compute_inverse(values, 1, 2);
    }

    #[inline]
    fn inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]) {
        self.compute_inverse(values, 1, 1);
    }

    #[inline]
    fn transform_monomial(
        &self,
        coeff: Self::ValueT,
        degree: usize,
        values: &mut [<Self as NttTable>::ValueT],
    ) {
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
        let modulus = self.q;

        let mask = usize::MAX >> (usize::BITS - log_n - 1);

        if coeff == 1 {
            values
                .iter_mut()
                .zip(&self.reverse_lsbs)
                .for_each(|(v, &i)| {
                    let index = ((2 * i + 1) * degree) & mask;
                    *v = unsafe { *self.ordinal_root_powers.get_unchecked(index) };
                });
        } else if coeff == self.q - 1 {
            values
                .iter_mut()
                .zip(&self.reverse_lsbs)
                .for_each(|(v, &i)| {
                    let index = (((2 * i + 1) * degree) & mask) ^ n;
                    *v = unsafe { *self.ordinal_root_powers.get_unchecked(index) };
                });
        } else {
            let mf_coeff = MultiplyFactor::new(coeff, 64, modulus);

            values
                .iter_mut()
                .zip(&self.reverse_lsbs)
                .for_each(|(v, &i)| {
                    let index = ((2 * i + 1) * degree) & mask;
                    let t = unsafe { *self.ordinal_root_powers.get_unchecked(index) };
                    *v = mf_coeff.mul_modulo::<64>(t, modulus);
                });
        }
    }

    #[inline]
    fn transform_coeff_one_monomial(
        &self,
        degree: usize,
        values: &mut [<Self as NttTable>::ValueT],
    ) {
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
                *v = unsafe { *self.ordinal_root_powers.get_unchecked(index) };
            });
    }

    #[inline]
    fn transform_coeff_minus_one_monomial(
        &self,
        degree: usize,
        values: &mut [<Self as NttTable>::ValueT],
    ) {
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
                *v = unsafe { *self.ordinal_root_powers.get_unchecked(index) };
            });
    }
}

#[cfg(test)]
mod tests {
    use primus_modulus::BarrettModulus;

    use super::*;

    #[test]
    fn test_hexl() {
        let _table = HexlNttTable::new(10, BarrettModulus::new(132120577)).unwrap();
    }
}
