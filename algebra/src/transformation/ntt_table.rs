use crate::field::NTTField;
use crate::polynomial::{NTTPolynomial, Polynomial};

use super::AbstractNTT;

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
}

impl<F> NTTTable<F>
where
    F: NTTField<Table = Self>,
{
    /// Creates a new [`NTTTable<F>`].
    #[inline]
    pub fn new(
        root: F,
        inv_root: F,
        coeff_count_power: u32,
        coeff_count: usize,
        inv_degree: <F as NTTField>::Root,
        root_powers: Vec<<F as NTTField>::Root>,
        inv_root_powers: Vec<<F as NTTField>::Root>,
    ) -> Self {
        Self {
            root,
            inv_root,
            coeff_count_power,
            coeff_count,
            inv_degree,
            root_powers,
            inv_root_powers,
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
}

impl<F> AbstractNTT<F> for NTTTable<F>
where
    F: NTTField<Table = Self>,
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

    fn transform_slice_lazy(&self, values: &mut [F]) {
        let log_n = self.coeff_count_power();

        debug_assert_eq!(values.len(), 1 << log_n);

        let mut root: <F as NTTField>::Root;
        let mut u: F;
        let mut v: F;

        let roots = self.root_powers();
        let mut root_iter = roots[1..].iter().copied();

        for gap in (0..log_n).rev().map(|x| 1usize << x) {
            for vc in values.chunks_exact_mut(gap << 1) {
                root = root_iter.next().unwrap();
                let (v0, v1) = vc.split_at_mut(gap);
                for (i, j) in std::iter::zip(v0, v1) {
                    u = i.reduce_lazy();
                    v = (*j).mul_root_lazy(root);
                    *i = u.add_no_reduce(v);
                    *j = u.sub_lazy(v);
                }
            }
        }
    }

    fn inverse_transform_slice_lazy(&self, values: &mut [F]) {
        let log_n = self.coeff_count_power();

        debug_assert_eq!(values.len(), 1 << log_n);

        let mut root: <F as NTTField>::Root;
        let mut u: F;
        let mut v: F;

        let roots = self.inv_root_powers();
        let mut root_iter = roots[1..].iter().copied();

        for gap in (0..log_n - 1).map(|x| 1usize << x) {
            for vc in values.chunks_exact_mut(gap << 1) {
                root = root_iter.next().unwrap();
                let (v0, v1) = vc.split_at_mut(gap);
                for (i, j) in std::iter::zip(v0, v1) {
                    u = *i;
                    v = *j;
                    *i = u.add_lazy(v);
                    *j = u.sub_lazy(v).mul_root_lazy(root);
                }
            }
        }

        let gap = 1 << (log_n - 1);

        let scalar = self.inv_degree();

        root = root_iter.next().unwrap();

        let scaled_r = F::from_root(root).mul_root(scalar).to_root();
        let (v0, v1) = values.split_at_mut(gap);
        for (i, j) in std::iter::zip(v0, v1) {
            u = *i;
            v = *j;
            *i = u.add_no_reduce(v).mul_root_lazy(scalar);
            *j = u.sub_lazy(v).mul_root_lazy(scaled_r);
        }
    }

    #[inline]
    fn transform_slice(&self, values: &mut [F]) {
        self.transform_slice_lazy(values);
        values.iter_mut().for_each(NTTField::normalize_4p);
    }

    #[inline]
    fn inverse_transform_slice(&self, values: &mut [F]) {
        self.inverse_transform_slice_lazy(values);
        values.iter_mut().for_each(NTTField::normalize_2p);
    }
}
