use primus_data::{DataMut, RawData};
use primus_factor::FactorBase;
use primus_factor::{FactorMul, LazyFactorMul, ShoupFactor};
use primus_integer::FheUint;
use primus_modulo::{AddModulo, ModuloOnce, ModuloOnceAssign};
use primus_modulus::CompactModulus;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;
use primus_reduce::prelude::*;

use crate::{NttError, reverse::ReverseLsbs, root::PrimitiveRoot};

use super::NttTable;

/// This struct store the pre-computed data for number theory transform and
/// inverse number theory transform.
///
/// ## The structure members meet the following conditions:
///
/// 1. `n = 1 << log_n`
/// 1. `root^{n} ≡ -1 (mod modulus)`
/// 1. `root * inv_root ≡ 1 (mod modulus)`
/// 1. `n * inv_n ≡ 1 (mod modulus)`
/// 1. `root_powers` holds 1~(n-1)-th powers of root in bit-reversed order, the 0-th power is left unset.
/// 1. `inv_root_powers` holds 1~(n-1)-th powers of inverse root in scrambled order, the 0-th power is left unset.
///
/// ## Compare three orders:
///
/// ```plain
/// normal order:        0  1  2  3  4  5  6  7
///
/// bit-reversed order:  0  4  2  6  1  5  3  7
///                         -  ----  ----------
/// scrambled order:     0  1  5  3  7  2  6  4
///                         ----------  ----  -
/// ```
pub struct UintNttTable<T: FheUint> {
    root: T,
    inv_root: T,
    modulus: T,
    log_n: u32,
    n: usize,
    inv_n: ShoupFactor<T>,
    root_powers: Vec<ShoupFactor<T>>,
    inv_root_powers: Vec<ShoupFactor<T>>,
    ordinal_root_powers: Vec<ShoupFactor<T>>,
    reverse_lsbs: Vec<usize>,
}

impl<T: FheUint> UintNttTable<T> {
    /// Returns the root of this [`UintNttTable<T>`].
    #[inline]
    pub fn root(&self) -> T {
        self.root
    }

    /// Returns the inverse element of the root of this [`UintNttTable<T>`].
    #[inline]
    pub fn inv_root(&self) -> T {
        self.inv_root
    }

    /// Returns the modulus of this [`UintNttTable<T>`].
    #[inline]
    pub fn modulus(&self) -> T {
        self.modulus
    }

    /// Returns the log n of this [`UintNttTable<T>`].
    #[inline]
    pub fn log_n(&self) -> u32 {
        self.log_n
    }

    /// Returns the n of this [`UintNttTable<T>`].
    #[inline]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Returns the inverse element of the n of this [`UintNttTable<T>`].
    #[inline]
    pub fn inv_n(&self) -> ShoupFactor<T> {
        self.inv_n
    }

    /// Returns a reference to the root powers of this [`UintNttTable<T>`].
    #[inline]
    pub fn root_powers(&self) -> &[ShoupFactor<T>] {
        &self.root_powers
    }

    /// Returns a reference to the inverse elements of the root powers of this [`UintNttTable<T>`].
    #[inline]
    pub fn inv_root_powers(&self) -> &[ShoupFactor<T>] {
        &self.inv_root_powers
    }

    /// Returns a reference to the ordinal root powers of this [`UintNttTable<T>`].
    #[inline]
    pub fn ordinal_root_powers(&self) -> &[ShoupFactor<T>] {
        &self.ordinal_root_powers
    }

    /// Returns a reference to the reverse lsbs of this [`UintNttTable<T>`].
    #[inline]
    pub fn reverse_lsbs(&self) -> &[usize] {
        &self.reverse_lsbs
    }
}

impl<T: FheUint> NttTable for UintNttTable<T> {
    type ValueT = T;

    #[inline]
    fn new<M>(log_n: u32, modulus: M) -> Result<Self, NttError<Self::ValueT>>
    where
        M: FieldContext<Self::ValueT>,
    {
        let root = <T as PrimitiveRoot>::try_minimal_primitive_root(log_n + 1, modulus)?;

        let modulus = unsafe { modulus.value_unchecked() };

        let n = 1usize << log_n;
        let to_root_type = |x| -> ShoupFactor<T> { <ShoupFactor<T>>::new(x, modulus) };

        let root_one = to_root_type(T::ONE);
        let root_factor = to_root_type(root);

        let mut power = root;

        let mut ordinal_root_powers = vec![<ShoupFactor<T>>::default(); n * 2];
        let mut iter = ordinal_root_powers.iter_mut();
        *iter.next().unwrap() = root_one;
        *iter.next().unwrap() = root_factor;
        for root_power in iter {
            power = root_factor.factor_mul_modulo(power, modulus);
            *root_power = to_root_type(power);
        }

        let inv_root = ordinal_root_powers.last().unwrap().value();

        debug_assert_eq!(root_factor.factor_mul_modulo(inv_root, modulus), T::ONE);

        let reverse_lsbs: Vec<usize> = (0..n).map(|i| i.reverse_lsbs(log_n)).collect();

        let mut root_powers = vec![<ShoupFactor<T>>::default(); n];
        root_powers[0] = root_one;
        for (&root_power, &i) in ordinal_root_powers[0..n].iter().zip(reverse_lsbs.iter()) {
            root_powers[i] = root_power;
        }

        let mut inv_root_powers = vec![<ShoupFactor<T>>::default(); n];
        inv_root_powers[0] = root_one;
        for (&inv_root_power, &i) in ordinal_root_powers[n + 1..]
            .iter()
            .rev()
            .zip(reverse_lsbs.iter())
        {
            inv_root_powers[i + 1] = inv_root_power;
        }

        let n_cast =
            T::try_from(n).map_err(|_| NttError::DegreeConversionErr { degree: n, modulus })?;

        if n_cast >= modulus {
            return Err(NttError::DegreeTooLarge { degree: n, modulus });
        }

        let inv_n = to_root_type(CompactModulus(modulus).reduce_inv(n_cast));

        Ok(Self {
            root,
            inv_root,
            modulus,
            log_n,
            n,
            inv_n,
            root_powers,
            inv_root_powers,
            ordinal_root_powers,
            reverse_lsbs,
        })
    }

    #[inline(always)]
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
        debug_assert_eq!(poly.len(), self.n);

        let modulus = self.modulus();
        let twice_modulus = modulus << 1u32;

        let roots = self.root_powers();
        let mut root_iter = roots[1..].iter().copied();

        for gap in (0..self.log_n).rev().map(|x| 1usize << x) {
            for vc in poly.chunks_exact_mut(gap << 1) {
                let root = root_iter.next().unwrap();
                let (v0, v1) = vc.split_at_mut(gap);
                for (i, j) in core::iter::zip(v0, v1) {
                    let u = (*i).modulo_once(CompactModulus(twice_modulus));
                    let v = root.lazy_factor_mul_modulo(*j, modulus);
                    *i = u + v;
                    *j = u + twice_modulus - v;
                }
            }
        }
    }

    fn transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]) {
        self.lazy_transform_slice(poly);

        let modulus = self.modulus();
        let twice_modulus = modulus << 1u32;
        poly.iter_mut().for_each(|v| {
            *v = (*v)
                .modulo_once(CompactModulus(twice_modulus))
                .modulo_once(CompactModulus(modulus));
        });
    }

    fn lazy_inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]) {
        debug_assert_eq!(values.len(), self.n);

        let log_n = self.log_n;

        let modulus = self.modulus();
        let twice_modulus = modulus << 1u32;

        let roots = self.inv_root_powers();
        let mut root_iter = roots[1..].iter().copied();

        for gap in (0..log_n - 1).map(|x| 1usize << x) {
            for vc in values.chunks_exact_mut(gap << 1) {
                let root = root_iter.next().unwrap();
                let (v0, v1) = vc.split_at_mut(gap);
                for (i, j) in core::iter::zip(v0, v1) {
                    let u = *i;
                    let v = *j;
                    *i = u.add_modulo(v, CompactModulus(twice_modulus));
                    *j = root.lazy_factor_mul_modulo(u + twice_modulus - v, modulus);
                }
            }
        }

        let gap = 1 << (log_n - 1);

        let scalar = self.inv_n();
        let scaled_r = root_iter
            .next()
            .unwrap()
            .factor_mul_modulo(scalar.value(), modulus);
        let scaled_r = ShoupFactor::new(scaled_r, modulus);

        let (v0, v1) = values.split_at_mut(gap);
        for (i, j) in core::iter::zip(v0, v1) {
            let u = *i;
            let v = *j;
            *i = scalar.factor_mul_modulo(u + v, modulus);
            *j = scaled_r.factor_mul_modulo(u + twice_modulus - v, modulus);
        }
    }

    fn inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]) {
        self.lazy_inverse_transform_slice(values);

        let modulus = self.modulus();
        values.iter_mut().for_each(|v| {
            v.modulo_once_assign(CompactModulus(modulus));
        });
    }

    fn transform_monomial(
        &self,
        coeff: Self::ValueT,
        degree: usize,
        values: &mut [<Self as NttTable>::ValueT],
    ) {
        if coeff.is_zero() {
            values.fill(T::ZERO);
            return;
        }

        if degree == 0 {
            values.fill(coeff);
            return;
        }

        let n = self.n;
        let log_n = self.log_n;
        debug_assert_eq!(values.len(), n);
        let modulus = self.modulus();

        let mask = usize::MAX >> (usize::BITS - log_n - 1);

        if coeff.is_one() {
            values
                .iter_mut()
                .zip(&self.reverse_lsbs)
                .for_each(|(v, &i)| {
                    let index = ((2 * i + 1) * degree) & mask;
                    *v = unsafe { *self.ordinal_root_powers.get_unchecked(index) }.value();
                });
        } else if coeff == self.modulus() - T::ONE {
            values
                .iter_mut()
                .zip(&self.reverse_lsbs)
                .for_each(|(v, &i)| {
                    let index = (((2 * i + 1) * degree) & mask) ^ n;
                    *v = unsafe { *self.ordinal_root_powers.get_unchecked(index) }.value();
                });
        } else {
            values
                .iter_mut()
                .zip(&self.reverse_lsbs)
                .for_each(|(v, &i)| {
                    let index = ((2 * i + 1) * degree) & mask;
                    *v = unsafe { *self.ordinal_root_powers.get_unchecked(index) }
                        .factor_mul_modulo(coeff, modulus);
                });
        }
    }

    fn transform_coeff_one_monomial(
        &self,
        degree: usize,
        values: &mut [<Self as NttTable>::ValueT],
    ) {
        if degree == 0 {
            values.fill(T::ONE);
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
                *v = unsafe { *self.ordinal_root_powers.get_unchecked(index) }.value();
            });
    }

    fn transform_coeff_minus_one_monomial(
        &self,
        degree: usize,
        values: &mut [<Self as NttTable>::ValueT],
    ) {
        if degree == 0 {
            values.fill(self.modulus() - T::ONE);
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
                *v = unsafe { *self.ordinal_root_powers.get_unchecked(index) }.value();
            });
    }
}
