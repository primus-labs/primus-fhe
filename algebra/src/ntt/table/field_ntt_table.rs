use num_traits::{ConstOne, ConstZero, One, Zero};

use crate::{
    arith::PrimitiveRoot,
    modulus::{BarrettModulus, ShoupFactor},
    ntt::{NttTable, NumberTheoryTransform},
    polynomial::{FieldNttPolynomial, FieldPolynomial},
    reduce::{
        LazyReduceMul, LazyReduceMulAssign, ReduceAdd, ReduceInv, ReduceMul, ReduceMulAssign,
        ReduceOnce, ReduceOnceAssign,
    },
    utils::{Pool, ReverseLsbs},
    AlgebraError, Field, NttField,
};

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
pub struct FieldTableWithShoupRoot<F>
where
    F: Field<Modulus = BarrettModulus<<F as Field>::ValueT>> + NttField<Table = Self>,
{
    root: <F as Field>::ValueT,
    inv_root: <F as Field>::ValueT,
    modulus: BarrettModulus<<F as Field>::ValueT>,
    log_n: u32,
    n: usize,
    inv_n: ShoupFactor<<F as Field>::ValueT>,
    root_powers: Vec<ShoupFactor<<F as Field>::ValueT>>,
    inv_root_powers: Vec<ShoupFactor<<F as Field>::ValueT>>,
    ordinal_root_powers: Vec<ShoupFactor<<F as Field>::ValueT>>,
    reverse_lsbs: Vec<usize>,
    pool: Pool<Vec<<F as Field>::ValueT>>,
}

impl<F> FieldTableWithShoupRoot<F>
where
    F: Field<Modulus = BarrettModulus<<F as Field>::ValueT>> + NttField<Table = Self>,
{
    /// Returns the root of this [`FieldTableWithShoupRoot<F>`].
    #[inline]
    pub fn root(&self) -> <F as Field>::ValueT {
        self.root
    }

    /// Returns the inverse element of the root of this [`FieldTableWithShoupRoot<F>`].
    #[inline]
    pub fn inv_root(&self) -> <F as Field>::ValueT {
        self.inv_root
    }

    /// Returns the modulus of this [`FieldTableWithShoupRoot<F>`].
    #[inline]
    pub fn modulus(&self) -> BarrettModulus<<F as Field>::ValueT> {
        self.modulus
    }

    /// Returns the log n of this [`FieldTableWithShoupRoot<F>`].
    #[inline]
    pub fn log_n(&self) -> u32 {
        self.log_n
    }

    /// Returns the n of this [`FieldTableWithShoupRoot<F>`].
    #[inline]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Returns the inverse element of the n of this [`FieldTableWithShoupRoot<F>`].
    #[inline]
    pub fn inv_n(&self) -> ShoupFactor<<F as Field>::ValueT> {
        self.inv_n
    }

    /// Returns a reference to the root powers of this [`FieldTableWithShoupRoot<F>`].
    #[inline]
    pub fn root_powers(&self) -> &[ShoupFactor<<F as Field>::ValueT>] {
        &self.root_powers
    }

    /// Returns a reference to the inverse elements of the root powers of this [`FieldTableWithShoupRoot<F>`].
    #[inline]
    pub fn inv_root_powers(&self) -> &[ShoupFactor<<F as Field>::ValueT>] {
        &self.inv_root_powers
    }

    /// Returns a reference to the ordinal root powers of this [`FieldTableWithShoupRoot<F>`].
    #[inline]
    pub fn ordinal_root_powers(&self) -> &[ShoupFactor<<F as Field>::ValueT>] {
        &self.ordinal_root_powers
    }

    /// Returns a reference to the reverse lsbs of this [`FieldTableWithShoupRoot<F>`].
    #[inline]
    pub fn reverse_lsbs(&self) -> &[usize] {
        &self.reverse_lsbs
    }
}

impl<F> NttTable for FieldTableWithShoupRoot<F>
where
    F: Field<Modulus = BarrettModulus<<F as Field>::ValueT>> + NttField<Table = Self>,
{
    type ValueT = <F as Field>::ValueT;

    type ModulusT = <F as Field>::Modulus;

    fn new(modulus: Self::ModulusT, log_n: u32) -> Result<Self, crate::AlgebraError> {
        let n = 1usize << log_n;

        let modulus_value = F::MODULUS_VALUE;
        let to_root_type =
            |x| -> ShoupFactor<<F as Field>::ValueT> { ShoupFactor::new(x, modulus_value) };

        let root = modulus.try_minimal_primitive_root(log_n + 1)?;

        let root_one = to_root_type(ConstOne::ONE);
        let root_factor = to_root_type(root);

        let mut power = root;

        let mut ordinal_root_powers = vec![ShoupFactor::default(); n * 2];
        let mut iter = ordinal_root_powers.iter_mut();
        *iter.next().unwrap() = root_one;
        *iter.next().unwrap() = root_factor;
        for root_power in iter {
            modulus_value.reduce_mul_assign(&mut power, root_factor);
            *root_power = to_root_type(power);
        }

        let inv_root = ordinal_root_powers.last().unwrap().value();

        debug_assert_eq!(
            modulus_value.reduce_mul(inv_root, root_factor),
            ConstOne::ONE
        );

        let reverse_lsbs: Vec<usize> = (0..n).map(|i| i.reverse_lsbs(log_n)).collect();

        let mut root_powers = vec![ShoupFactor::default(); n];
        root_powers[0] = root_one;
        for (&root_power, &i) in ordinal_root_powers[0..n].iter().zip(reverse_lsbs.iter()) {
            root_powers[i] = root_power;
        }

        let mut inv_root_powers = vec![ShoupFactor::default(); n];
        inv_root_powers[0] = root_one;
        for (&inv_root_power, &i) in ordinal_root_powers[n + 1..]
            .iter()
            .rev()
            .zip(reverse_lsbs.iter())
        {
            inv_root_powers[i + 1] = inv_root_power;
        }

        let n_cast =
            <<F as Field>::ValueT>::try_from(n).map_err(|_| AlgebraError::DegreeConversionErr {
                degree: n,
                modulus: Box::new(modulus_value),
            })?;

        if n_cast >= modulus_value {
            return Err(AlgebraError::TooLargeDegreeErr {
                degree: n,
                modulus: Box::new(modulus_value),
            });
        }

        let inv_n = to_root_type(modulus_value.reduce_inv(n_cast));

        let pool = Pool::new_with(2, || vec![ConstZero::ZERO; n]);

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
            pool,
        })
    }

    #[inline(always)]
    fn dimension(&self) -> usize {
        self.n
    }
}

impl<F> NumberTheoryTransform for FieldTableWithShoupRoot<F>
where
    F: Field<Modulus = BarrettModulus<<F as Field>::ValueT>> + NttField<Table = Self>,
{
    type CoeffPoly = FieldPolynomial<F>;

    type NttPoly = FieldNttPolynomial<F>;

    #[inline]
    fn transform_inplace(&self, mut poly: Self::CoeffPoly) -> Self::NttPoly {
        self.transform_slice(poly.as_mut_slice());
        <FieldNttPolynomial<F>>::new(poly.inner_data())
    }

    #[inline]
    fn inverse_transform_inplace(&self, mut values: Self::NttPoly) -> Self::CoeffPoly {
        self.inverse_transform_slice(values.as_mut_slice());
        <FieldPolynomial<F>>::new(values.inner_data())
    }

    #[inline]
    fn lazy_transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]) {
        debug_assert_eq!(poly.len(), self.n);

        let modulus_value = <F as Field>::MODULUS_VALUE;
        let twice_modulus_value = modulus_value << 1u32;

        let roots = self.root_powers();
        let mut root_iter = roots[1..].iter().copied();

        for gap in (0..self.log_n).rev().map(|x| 1usize << x) {
            for vc in poly.chunks_exact_mut(gap << 1) {
                let root = root_iter.next().unwrap();
                let (v0, v1) = vc.split_at_mut(gap);
                for (i, j) in core::iter::zip(v0, v1) {
                    let u = twice_modulus_value.reduce_once(*i);
                    let v = modulus_value.lazy_reduce_mul(root, *j);
                    *i = u + v;
                    *j = u + twice_modulus_value - v;
                }
            }
        }
    }

    #[inline]
    fn transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]) {
        self.lazy_transform_slice(poly);

        let modulus_value = <F as Field>::MODULUS_VALUE;
        let twice_modulus_value = modulus_value << 1u32;
        poly.iter_mut().for_each(|v| {
            let r = twice_modulus_value.reduce_once(*v);
            *v = modulus_value.reduce_once(r);
        });
    }

    #[inline]
    fn lazy_inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]) {
        debug_assert_eq!(values.len(), self.n);

        let log_n = self.log_n;

        let modulus_value = <F as Field>::MODULUS_VALUE;
        let twice_modulus_value = modulus_value << 1u32;

        let roots = self.inv_root_powers();
        let mut root_iter = roots[1..].iter().copied();

        for gap in (0..log_n - 1).map(|x| 1usize << x) {
            for vc in values.chunks_exact_mut(gap << 1) {
                let root = root_iter.next().unwrap();
                let (v0, v1) = vc.split_at_mut(gap);
                for (i, j) in core::iter::zip(v0, v1) {
                    let u = *i;
                    let v = *j;
                    *i = twice_modulus_value.reduce_add(u, v);
                    *j = modulus_value.lazy_reduce_mul(u + twice_modulus_value - v, root);
                }
            }
        }

        let gap = 1 << (log_n - 1);

        let scalar = self.inv_n();
        let scaled_r = modulus_value.reduce_mul(scalar.value(), root_iter.next().unwrap());
        let scaled_r = ShoupFactor::new(scaled_r, modulus_value);

        let (v0, v1) = values.split_at_mut(gap);
        for (i, j) in core::iter::zip(v0, v1) {
            let u = *i;
            let v = *j;
            *i = modulus_value.lazy_reduce_mul(u + v, scalar);
            *j = modulus_value.lazy_reduce_mul(u + twice_modulus_value - v, scaled_r);
        }
    }

    #[inline]
    fn inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]) {
        self.lazy_inverse_transform_slice(values);

        let modulus_value = <F as Field>::MODULUS_VALUE;
        values.iter_mut().for_each(|v| {
            modulus_value.reduce_once_assign(v);
        });
    }

    #[inline]
    fn transform_monomial(
        &self,
        coeff: Self::ValueT,
        degree: usize,
        values: &mut [<Self as NttTable>::ValueT],
    ) {
        if coeff.is_zero() {
            values.fill(ConstZero::ZERO);
            return;
        }

        if degree == 0 {
            values.fill(coeff);
            return;
        }

        let n = self.n;
        let log_n = self.log_n;
        debug_assert_eq!(values.len(), n);
        let modulus_value = <F as Field>::MODULUS_VALUE;

        let mask = usize::MAX >> (usize::BITS - log_n - 1);

        if coeff.is_one() {
            values
                .iter_mut()
                .zip(&self.reverse_lsbs)
                .for_each(|(v, &i)| {
                    let index = ((2 * i + 1) * degree) & mask;
                    *v = unsafe { *self.ordinal_root_powers.get_unchecked(index) }.value();
                });
        } else if coeff == <F as Field>::MINUS_ONE {
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
                    *v = modulus_value.reduce_mul(
                        unsafe { *self.ordinal_root_powers.get_unchecked(index) },
                        coeff,
                    );
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
            values.fill(ConstOne::ONE);
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

    #[inline]
    fn transform_coeff_minus_one_monomial(
        &self,
        degree: usize,
        values: &mut [<Self as NttTable>::ValueT],
    ) {
        if degree == 0 {
            values.fill(<F as Field>::MINUS_ONE);
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

    fn lazy_mul_assign(&self, a: &mut Self::CoeffPoly, b: &Self::CoeffPoly) {
        let mut bv = self.pool.try_get().map_or_else(
            || b.as_slice().to_vec(),
            |mut t| {
                t.copy_from_slice(b.as_slice());
                t
            },
        );

        self.lazy_transform_slice(a.as_mut_slice());
        self.lazy_transform_slice(bv.as_mut_slice());

        for (ai, &bi) in a.iter_mut().zip(bv.iter()) {
            self.modulus.lazy_reduce_mul_assign(ai, bi);
        }

        self.pool.store(bv);
        self.lazy_inverse_transform_slice(a.as_mut_slice());
    }

    #[inline]
    fn mul_assign(&self, a: &mut Self::CoeffPoly, b: &Self::CoeffPoly) {
        self.lazy_mul_assign(a, b);

        let modulus_value = self.modulus.value();
        a.iter_mut().for_each(|v| {
            modulus_value.reduce_once_assign(v);
        });
    }

    #[inline]
    fn lazy_mul_inplace(&self, a: &Self::CoeffPoly, b: &Self::CoeffPoly, c: &mut Self::CoeffPoly) {
        c.copy_from(a);
        self.lazy_mul_assign(c, b);
    }

    #[inline]
    fn mul_inplace(&self, a: &Self::CoeffPoly, b: &Self::CoeffPoly, c: &mut Self::CoeffPoly) {
        self.lazy_mul_inplace(a, b, c);

        let modulus_value = self.modulus.value();
        c.iter_mut().for_each(|v| {
            modulus_value.reduce_once_assign(v);
        });
    }
}
