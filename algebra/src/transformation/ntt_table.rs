use crate::modulus::ShoupFactor;
use crate::utils::ReverseLsbs;
use crate::{Field, NTTField, NTTPolynomial, Polynomial, Widening, WrappingOps};

use super::{AbstractNTT, MonomialNTT};

/// This struct store the pre-computed data for number theory transform and
/// inverse number theory transform.
///
/// ## The structure members meet the following conditions:
///
/// 1. `coeff_count` = 1 << `coeff_count_power`
/// 1. `root` ^ `2 * coeff_count` = -1 mod `modulus`
/// 1. `root` * `inv_root` = 1 mod `modulus`
/// 1. `coeff_count` * `inv_degree` = 1 mod `modulus`
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
#[derive(Debug)]
pub struct NTTTable<F>
where
    F: NTTField<Table = Self>,
{
    root: F,
    inv_root: F,
    coeff_count_power: u32,
    coeff_count: usize,
    inv_degree: <F as NTTField>::Root,
    root_powers: Vec<<F as NTTField>::Root>,
    inv_root_powers: Vec<<F as NTTField>::Root>,
    ordinal_root_powers: Vec<<F as NTTField>::Root>,
    reverse_lsbs: Vec<usize>,
}

impl<F> NTTTable<F>
where
    F: NTTField<Table = Self>,
{
    /// Creates a new [`NTTTable<F>`].
    #[inline]
    pub fn new(
        root: F,
        coeff_count_power: u32,
        ordinal_root_powers: Vec<<F as NTTField>::Root>,
    ) -> Self {
        let coeff_count = 1usize << coeff_count_power;

        let inv_root = F::from_root(*ordinal_root_powers.last().unwrap());

        debug_assert_eq!(root * inv_root, F::ONE);

        let root_one = ordinal_root_powers[0];

        let reverse_lsbs: Vec<usize> = (0..coeff_count)
            .map(|i| i.reverse_lsbs(coeff_count_power))
            .collect();

        let mut root_powers = vec![<F as NTTField>::Root::default(); coeff_count];
        root_powers[0] = root_one;
        for (&root_power, &i) in ordinal_root_powers[0..coeff_count]
            .iter()
            .zip(reverse_lsbs.iter())
        {
            root_powers[i] = root_power;
        }

        let mut inv_root_powers = vec![<F as NTTField>::Root::default(); coeff_count];
        inv_root_powers[0] = root_one;
        for (&inv_root_power, &i) in ordinal_root_powers[coeff_count + 1..]
            .iter()
            .rev()
            .zip(reverse_lsbs.iter())
        {
            inv_root_powers[i + 1] = inv_root_power;
        }

        let inv_degree = <F as Field>::cast_from_usize(coeff_count).inv().to_root();

        Self {
            root,
            inv_root,
            coeff_count_power,
            coeff_count,
            inv_degree,
            root_powers,
            inv_root_powers,
            ordinal_root_powers,
            reverse_lsbs,
        }
    }

    /// Returns the root of this [`NTTTable<F>`].
    #[inline]
    pub fn root(&self) -> F {
        self.root
    }

    /// Returns the inverse element of the root of this [`NTTTable<F>`].
    #[inline]
    pub fn inv_root(&self) -> F {
        self.inv_root
    }

    /// Returns the coeff count power of this [`NTTTable<F>`].
    #[inline]
    pub fn coeff_count_power(&self) -> u32 {
        self.coeff_count_power
    }

    /// Returns the coeff count of this [`NTTTable<F>`].
    #[inline]
    pub fn coeff_count(&self) -> usize {
        self.coeff_count
    }

    /// Returns the inverse element of the degree of this [`NTTTable<F>`].
    #[inline]
    pub fn inv_degree(&self) -> <F as NTTField>::Root {
        self.inv_degree
    }

    /// Returns a reference to the root powers of this [`NTTTable<F>`].
    #[inline]
    pub fn root_powers(&self) -> &[<F as NTTField>::Root] {
        self.root_powers.as_ref()
    }

    /// Returns a reference to the inverse elements of the root powers of this [`NTTTable<F>`].
    #[inline]
    pub fn inv_root_powers(&self) -> &[<F as NTTField>::Root] {
        self.inv_root_powers.as_ref()
    }

    /// Returns a reference to the ordinal root powers of this [`NTTTable<F>`].
    #[inline]
    pub fn ordinal_root_powers(&self) -> &[<F as NTTField>::Root] {
        &self.ordinal_root_powers
    }
}

impl<F> MonomialNTT<F> for NTTTable<F>
where
    F: NTTField<Table = Self>,
{
    fn transform_monomial(&self, coeff: F, degree: usize, values: &mut [F]) {
        if coeff == F::ZERO {
            values.fill(F::ZERO);
            return;
        }

        if degree == 0 {
            values.fill(coeff);
            return;
        }

        let log_n = self.coeff_count_power();
        debug_assert_eq!(values.len(), 1 << log_n);

        let mask = usize::MAX >> (usize::BITS - log_n - 1);

        if coeff == F::ONE {
            values
                .iter_mut()
                .zip(&self.reverse_lsbs)
                .for_each(|(v, &i)| {
                    let index = ((2 * i + 1) * degree) & mask;
                    *v = F::from_root(unsafe { *self.ordinal_root_powers.get_unchecked(index) });
                })
        } else if coeff == F::NEG_ONE {
            values
                .iter_mut()
                .zip(&self.reverse_lsbs)
                .for_each(|(v, &i)| {
                    let index = ((2 * i + 1) * degree) & mask;
                    *v = F::from_root(unsafe { *self.ordinal_root_powers.get_unchecked(index) })
                        .neg();
                })
        } else {
            values
                .iter_mut()
                .zip(&self.reverse_lsbs)
                .for_each(|(v, &i)| {
                    let index = ((2 * i + 1) * degree) & mask;
                    *v = coeff.mul_root(unsafe { *self.ordinal_root_powers.get_unchecked(index) });
                })
        }
    }

    fn transform_coeff_one_monomial(&self, degree: usize, values: &mut [F]) {
        if degree == 0 {
            values.fill(F::ONE);
            return;
        }

        let log_n = self.coeff_count_power();
        debug_assert_eq!(values.len(), 1 << log_n);

        let mask = usize::MAX >> (usize::BITS - log_n - 1);

        values
            .iter_mut()
            .zip(&self.reverse_lsbs)
            .for_each(|(v, &i)| {
                let index = ((2 * i + 1) * degree) & mask;
                *v = F::from_root(unsafe { *self.ordinal_root_powers.get_unchecked(index) });
            })
    }
}

impl<F> AbstractNTT<F> for NTTTable<F>
where
    F: NTTField<Table = Self, Root = ShoupFactor<<F as Field>::Value>>,
{
    #[inline]
    fn transform(&self, polynomial: &Polynomial<F>) -> NTTPolynomial<F> {
        self.transform_inplace(polynomial.clone())
    }

    #[inline]
    fn transform_inplace(&self, mut polynomial: Polynomial<F>) -> NTTPolynomial<F> {
        self.transform_slice(polynomial.as_mut_slice());
        NTTPolynomial::<F>::new(polynomial.data())
    }

    #[inline]
    fn inverse_transform(&self, ntt_polynomial: &NTTPolynomial<F>) -> Polynomial<F> {
        self.inverse_transform_inplace(ntt_polynomial.clone())
    }

    #[inline]
    fn inverse_transform_inplace(&self, mut ntt_polynomial: NTTPolynomial<F>) -> Polynomial<F> {
        self.inverse_transform_slice(ntt_polynomial.as_mut_slice());
        Polynomial::<F>::new(ntt_polynomial.data())
    }

    fn transform_slice(&self, values: &mut [F]) {
        let log_n = self.coeff_count_power();

        debug_assert_eq!(values.len(), 1 << log_n);

        let roots = self.root_powers();
        let mut root_iter = roots[1..].iter().copied();

        for gap in (0..log_n).rev().map(|x| 1usize << x) {
            for vc in values.chunks_exact_mut(gap << 1) {
                let root = root_iter.next().unwrap();
                let (v0, v1) = vc.split_at_mut(gap);
                for (i, j) in std::iter::zip(v0, v1) {
                    let u = guard(*i);
                    let v = mul_root_fast(*j, root);
                    *i = add_no_reduce(u, v);
                    *j = sub_fast(u, v);
                }
            }
        }

        values.iter_mut().for_each(ntt_normalize_assign);
    }

    fn inverse_transform_slice(&self, values: &mut [F]) {
        let log_n = self.coeff_count_power();

        debug_assert_eq!(values.len(), 1 << log_n);

        let roots = self.inv_root_powers();
        let mut root_iter = roots[1..].iter().copied();

        for gap in (0..log_n - 1).map(|x| 1usize << x) {
            for vc in values.chunks_exact_mut(gap << 1) {
                let root = root_iter.next().unwrap();
                let (v0, v1) = vc.split_at_mut(gap);
                for (i, j) in std::iter::zip(v0, v1) {
                    let u = *i;
                    let v = *j;
                    *i = add_fast(u, v);
                    *j = mul_root_fast(sub_fast(u, v), root);
                }
            }
        }

        let gap = 1 << (log_n - 1);

        let scalar = self.inv_degree();

        let scaled_r = F::from_root(root_iter.next().unwrap())
            .mul_root(scalar)
            .to_root();
        let (v0, v1) = values.split_at_mut(gap);
        for (i, j) in std::iter::zip(v0, v1) {
            let u = *i;
            let v = *j;
            *i = mul_root_fast(add_no_reduce(u, v), scalar);
            *j = mul_root_fast(sub_fast(u, v), scaled_r);
        }

        values.iter_mut().for_each(intt_normalize_assign);
    }
}

#[inline]
fn guard<F: Field>(a: F) -> F {
    if a.get() >= F::TWICE_MODULUS_INNER {
        F::new(a.get() - F::TWICE_MODULUS_INNER)
    } else {
        a
    }
}

#[inline]
fn ntt_normalize_assign<F: Field>(a: &mut F) {
    let mut r = a.get();
    if r >= F::TWICE_MODULUS_INNER {
        r = r - F::TWICE_MODULUS_INNER;
    }
    if r >= F::MODULUS_INNER {
        r = r - F::MODULUS_INNER;
    }
    a.set(r);
}

#[inline]
fn intt_normalize_assign<F: Field>(a: &mut F) {
    if a.get() >= F::MODULUS_INNER {
        a.set(a.get() - F::MODULUS_INNER)
    }
}

#[inline]
fn add_no_reduce<F: Field>(a: F, b: F) -> F {
    F::new(a.get() + b.get())
}

#[inline]
fn add_fast<F: Field>(a: F, b: F) -> F {
    let r = a.get() + b.get();
    if r >= F::TWICE_MODULUS_INNER {
        F::new(r - F::TWICE_MODULUS_INNER)
    } else {
        F::new(r)
    }
}

#[inline]
fn sub_fast<F: Field>(a: F, b: F) -> F {
    F::new(a.get() + F::TWICE_MODULUS_INNER - b.get())
}

#[inline]
fn mul_root_fast<F: NTTField>(a: F, root: ShoupFactor<F::Value>) -> F {
    let (_, hw) = a.get().widen_mul(root.quotient());
    F::new(
        root.value()
            .wrapping_mul(a.get())
            .wrapping_sub(hw.wrapping_mul(F::MODULUS_INNER)),
    )
}
