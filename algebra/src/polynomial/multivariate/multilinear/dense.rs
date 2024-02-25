use core::fmt;
use std::cmp::min;
use std::fmt::Debug;
use std::slice::{Iter, IterMut};
use std::ops::{Add, AddAssign, Index, Neg, Sub, SubAssign};

use num_traits::Zero;
use rand_distr::Distribution;

use crate::Random;
use crate::{
    polynomial::multivariate::Polynomial_,
    polynomial::multivariate::multilinear::MultilinearExtension
};

use crate::field::Field;

/// Stores a multilinear polynomial in dense evaluation form.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct DenseMultilinearExtension<F: Field> {
    /// The evaluation over {0,1}^`num_vars`
    pub evaluations: Vec<F>,
    /// Number of variables
    pub num_vars: usize,
}

impl<F: Field> DenseMultilinearExtension<F> {
    /// Construct a new polynomial from a list of evaluations where the index
    /// represents a point in {0,1}^`num_vars` in little endian form. For
    /// example, `0b1011` represents `P(1,1,0,1)`
    pub fn from_evaluations_slice(num_vars: usize, evaluations: &[F]) -> Self {
        Self::from_evaluations_vec(num_vars, evaluations.to_vec())
    }

    /// Construct a new polynomial from a list of evaluations where the index
    /// represents a point in {0,1}^`num_vars` in little endian form. For
    /// example, `0b1011` represents `P(1,1,0,1)`
    pub fn from_evaluations_vec(num_vars: usize, evaluations: Vec<F>) -> Self {
        assert_eq!(
            evaluations.len(),
            1 << num_vars,
            "The size of evaluations should be 2^num_vars."
        );

        Self {
            num_vars,
            evaluations,
        }
    }

    /// Returns an iterator that iterates over the evaluations over {0,1}^`num_vars`
    pub fn iter(&self) -> Iter<'_, F> {
        self.evaluations.iter()
    }

    /// Returns a mutable iterator that iterates over the evaluations over {0,1}^`num_vars`
    pub fn iter_mut(&mut self) -> IterMut<'_, F> {
        self.evaluations.iter_mut()
    }
}

impl<F: Field + Random> MultilinearExtension<F> for DenseMultilinearExtension<F>{
    fn num_vars(&self) -> usize {
        self.num_vars
    }

    fn rand<R>(num_vars: usize, rng: &mut R) -> Self 
    where 
        R: rand::Rng + rand::CryptoRng,
    {
        Self {
            num_vars,
            evaluations: F::standard_distribution()
                .sample_iter(rng)
                .take(1<<num_vars)
                .collect(),
        }
    }

    fn fix_variables(&self, partial_point: &[F]) -> Self {
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );
        let mut poly = self.evaluations.to_vec();
        let nv = self.num_vars;
        let dim = partial_point.len();
        // evaluate single variable of partial point from left to right
        for i in 1..dim + 1 {
            let r = partial_point[i-1];
            for b in 0..(1 << (nv-i)) {
                let left = poly[b << 1];
                let right = poly[ (b << 1) + 1];
                poly[b] = left + r * (right - left);
            }
        }
        Self::from_evaluations_slice(nv - dim, &poly[..(1 << (nv - dim))])
    }

    fn to_evaluations(&self) -> Vec<F> {
        self.evaluations.to_vec()
    }
}

impl<F: Field + Random> Polynomial_<F> for DenseMultilinearExtension<F> {
    type Point = Vec<F>;

    fn degree(&self) -> usize {
        self.num_vars
    }

    fn evaluate(&self, point: &Self::Point) -> F {
        assert_eq!(
            point.len(),
            self.num_vars,
            "The point size is invalid."
        );
        self.fix_variables(&point)[0]
    }
}

impl<F: Field> Index<usize> for DenseMultilinearExtension<F> {
    type Output = F;

    /// Returns the evaluation of the polynomial at a point represented by index.
    ///
    /// Index represents a vector in {0,1}^`num_vars` in little endian form. For
    /// example, `0b1011` represents `P(1,1,0,1)`
    ///
    /// For dense multilinear polynomial, `index` takes constant time.
    fn index(&self, index: usize) -> &Self::Output {
        &self.evaluations[index]
    }
}

impl<'a, 'b, F: Field> Add <&'a DenseMultilinearExtension<F>> for &'b DenseMultilinearExtension<F> {
    type Output = DenseMultilinearExtension<F>;

    fn add(self, rhs: &'a DenseMultilinearExtension<F>) -> Self::Output {
        // handle constant zero case
        if rhs.is_zero() {
            return self.clone();
        }
        if self.is_zero() {
            return rhs.clone();
        }
        assert_eq!(self.num_vars, rhs.num_vars);
        let result: Vec<F> = self
            .iter()
            .zip(rhs.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        Self::Output::from_evaluations_vec(self.num_vars, result)
    }
}

impl<F:Field> Debug for DenseMultilinearExtension<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "DenseML(nv = {}, evaluations = [", self.num_vars)?;
        for i in 0..min(4, self.evaluations.len()) {
            write!(f, "{:?}", self.evaluations[i])?;
        }
        if self.evaluations.len() < 4 {
            write!(f, "])")?;
        } else {
            write!(f, "...])")?;
        }
        Ok(())
    }
}

impl<F: Field> Add for DenseMultilinearExtension<F> {
    type Output = DenseMultilinearExtension<F>;

    fn add(self, other: DenseMultilinearExtension<F>) -> Self {
        &self + &other
    }
}

impl<F: Field> Zero for DenseMultilinearExtension<F> {
    fn zero() -> Self {
        Self {
            num_vars: 0,
            evaluations: vec![F::zero()],
        }
    }

    fn is_zero(&self) -> bool {
        self.num_vars == 0 && self.evaluations[0].is_zero()
    }
}

impl<F: Field> AddAssign for DenseMultilinearExtension<F> {
    fn add_assign(&mut self, rhs: Self) {
        *self = &*self + &rhs;
    }
}

impl<'a, F: Field> AddAssign<&'a DenseMultilinearExtension<F>> for DenseMultilinearExtension<F> {
    fn add_assign(&mut self, rhs: &'a DenseMultilinearExtension<F>) {
        *self = &*self + rhs;
    }
}

impl<'a, F: Field> AddAssign<(F, &'a DenseMultilinearExtension<F>)>
    for DenseMultilinearExtension<F> 
{
    fn add_assign(&mut self, (f, rhs): (F, &'a DenseMultilinearExtension<F>)) {
        let rhs = Self {
            num_vars: rhs.num_vars,
            evaluations: rhs.iter().map(|x| f * x).collect(),
        };
        *self = &*self + &rhs;
    }
}

impl<F: Field> Neg for DenseMultilinearExtension<F> {
    type Output = DenseMultilinearExtension<F>;
    fn neg(self) -> Self::Output {
        Self::Output {
            num_vars: self.num_vars,
            evaluations: self.evaluations.iter().map(|x| -(*x)).collect(),
        }
    }
}

impl<F: Field> Sub for DenseMultilinearExtension<F> {
    type Output = DenseMultilinearExtension<F>;

    fn sub(self, rhs: Self) -> Self {
        &self - &rhs
    }
}

impl<'a, 'b, F: Field> Sub<&'a DenseMultilinearExtension<F>> for &'b DenseMultilinearExtension<F> {
    type Output = DenseMultilinearExtension<F>;

    fn sub(self, rhs: &'a DenseMultilinearExtension<F>) -> Self::Output {
        self + &rhs.clone().neg()
    }
}

impl<F: Field> SubAssign for DenseMultilinearExtension<F> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = &*self - &rhs;
    }
}

impl<'a, F: Field> SubAssign<&'a DenseMultilinearExtension<F>> for DenseMultilinearExtension<F> {
    fn sub_assign(&mut self, rhs: &'a DenseMultilinearExtension<F>) {
        *self = &*self - rhs;
    }
}