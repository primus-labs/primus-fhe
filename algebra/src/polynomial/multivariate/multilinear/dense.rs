// It is derived from https://github.com/arkworks-rs/sumcheck.

use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Index, Neg, Sub, SubAssign};
use std::slice::{Iter, IterMut};

use num_traits::Zero;
use rand_distr::Distribution;

use crate::{AbstractExtensionField, Field, FieldUniformSampler};

use super::dense_base::DenseMultilinearExtensionBase;
use super::MultilinearExtension;

/// Stores a multilinear polynomial in dense evaluation form.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct DenseMultilinearExtension<F: Field, EF: AbstractExtensionField<F>> {
    /// The evaluation over {0,1}^`num_vars`
    pub evaluations: Vec<EF>,
    /// Number of variables
    pub num_vars: usize,
    _marker: PhantomData<F>,
}

impl<F: Field, EF: AbstractExtensionField<F>> DenseMultilinearExtension<F, EF> {
    /// Construct a new polynomial from a list of evaluations where the index
    /// represents a point in {0,1}^`num_vars` in little endian form. For
    /// example, `0b1011` represents `P(1,1,0,1)`
    #[inline]
    pub fn from_evaluations_slice(num_vars: usize, evaluations: &[EF]) -> Self {
        assert_eq!(
            evaluations.len(),
            1 << num_vars,
            "The size of evaluations should be 2^num_vars."
        );
        Self::from_evaluations_vec(num_vars, evaluations.to_vec())
    }

    /// Construct a new polynomial from a list of evaluations where the index
    /// represents a point in {0,1}^`num_vars` in little endian form. For
    /// example, `0b1011` represents `P(1,1,0,1)`
    #[inline]
    pub fn from_evaluations_vec(num_vars: usize, evaluations: Vec<EF>) -> Self {
        assert_eq!(
            evaluations.len(),
            1 << num_vars,
            "The size of evaluations should be 2^num_vars."
        );

        Self {
            num_vars,
            evaluations,
            _marker: PhantomData,
        }
    }

    /// Construct a new polynomial from DenseMultilinearExtensionBase where the evaluations are in Field
    #[inline]
    pub fn from_base(mle_base: &DenseMultilinearExtensionBase<F>) -> Self {
        Self {
            num_vars: mle_base.num_vars,
            evaluations: mle_base
                .evaluations
                .iter()
                .map(|x| EF::from_base(*x))
                .collect(),
            _marker: PhantomData,
        }
    }

    /// Returns an iterator that iterates over the evaluations over {0,1}^`num_vars`
    #[inline]
    pub fn iter(&self) -> Iter<'_, EF> {
        self.evaluations.iter()
    }

    /// Returns a mutable iterator that iterates over the evaluations over {0,1}^`num_vars`
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, EF> {
        self.evaluations.iter_mut()
    }

    /// Split the mle into two mles with one less variable, eliminating the far right variable
    /// original evaluations: f(x, b) for x \in \{0, 1\}^{k-1} and b\{0, 1\}
    /// resulting two mles: f0(x) = f(x, 0) for x \in \{0, 1\}^{k-1} and f1(x) = f(x, 1) for x \in \{0, 1\}^{k-1}
    pub fn split_halves(&self) -> (Self, Self) {
        let left = Self::from_evaluations_slice(
            self.num_vars - 1,
            &self.evaluations[0..1 << (self.num_vars - 1)],
        );
        let right = Self::from_evaluations_slice(
            self.num_vars - 1,
            &self.evaluations[1 << (self.num_vars - 1)..],
        );
        (left, right)
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> MultilinearExtension<F, EF>
    for DenseMultilinearExtension<F, EF>
{
    type Point = [EF];

    #[inline]
    fn num_vars(&self) -> usize {
        self.num_vars
    }

    #[inline]
    fn evaluate(&self, point: &Self::Point) -> EF {
        assert_eq!(point.len(), self.num_vars, "The point size is invalid.");
        self.fix_variables(point)[0]
    }

    #[inline]
    fn random<R>(num_vars: usize, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self {
            num_vars,
            evaluations: FieldUniformSampler::new()
                .sample_iter(rng)
                .take(1 << num_vars)
                .collect(),
            _marker: PhantomData,
        }
    }

    fn fix_variables(&self, partial_point: &[EF]) -> Self {
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );
        let mut poly = self.evaluations.to_vec();
        let nv = self.num_vars;
        let dim = partial_point.len();
        // evaluate nv variable of partial point from left to right
        // with dim rounds and \sum_{i=1}^{dim} 2^(nv - i)
        // (If dim = nv, then the complexity is 2^{nv}.)
        for i in 1..dim + 1 {
            // fix a single variable to evaluate (1 << (nv - i)) evaluations from the last round
            // with complexity of 2^(1 << (nv - i)) field multiplications
            let r = partial_point[i - 1];
            for b in 0..(1 << (nv - i)) {
                let left = poly[b << 1];
                let right = poly[(b << 1) + 1];
                poly[b] = left + r * (right - left);
            }
        }
        poly.truncate(1 << (nv - dim));
        Self::from_evaluations_vec(nv - dim, poly)
    }

    #[inline]
    fn to_evaluations(&self) -> Vec<EF> {
        self.evaluations.to_vec()
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> Index<usize> for DenseMultilinearExtension<F, EF> {
    type Output = EF;

    /// Returns the evaluation of the polynomial at a point represented by index.
    ///
    /// Index represents a vector in {0,1}^`num_vars` in little endian form. For
    /// example, `0b1011` represents `P(1,1,0,1)`
    ///
    /// For dense multilinear polynomial, `index` takes constant time.
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.evaluations[index]
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> Debug for DenseMultilinearExtension<F, EF> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(f, "DenseML(nv = {}, evaluations = [", self.num_vars)?;
        for i in 0..4.min(self.evaluations.len()) {
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

impl<F: Field, EF: AbstractExtensionField<F>> Zero for DenseMultilinearExtension<F, EF> {
    #[inline]
    fn zero() -> Self {
        Self {
            num_vars: 0,
            evaluations: vec![EF::zero()],
            _marker: PhantomData,
        }
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.num_vars == 0 && self.evaluations[0].is_zero()
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> Add for DenseMultilinearExtension<F, EF> {
    type Output = DenseMultilinearExtension<F, EF>;
    #[inline]
    fn add(mut self, rhs: DenseMultilinearExtension<F, EF>) -> Self {
        self.add_assign(rhs);
        self
    }
}

impl<'a, F: Field, EF: AbstractExtensionField<F>> Add<&'a DenseMultilinearExtension<F, EF>>
    for DenseMultilinearExtension<F, EF>
{
    type Output = DenseMultilinearExtension<F, EF>;
    #[inline]
    fn add(mut self, rhs: &'a DenseMultilinearExtension<F, EF>) -> Self::Output {
        self.add_assign(rhs);
        self
    }
}

impl<'a, 'b, F: Field, EF: AbstractExtensionField<F>> Add<&'a DenseMultilinearExtension<F, EF>>
    for &'b DenseMultilinearExtension<F, EF>
{
    type Output = DenseMultilinearExtension<F, EF>;

    #[inline]
    fn add(self, rhs: &'a DenseMultilinearExtension<F, EF>) -> Self::Output {
        // handle constant zero case
        if rhs.is_zero() {
            return self.clone();
        }
        if self.is_zero() {
            return rhs.clone();
        }
        assert_eq!(self.num_vars, rhs.num_vars);
        let result: Vec<EF> = self.iter().zip(rhs.iter()).map(|(&a, b)| a + b).collect();
        Self::Output::from_evaluations_vec(self.num_vars, result)
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> AddAssign for DenseMultilinearExtension<F, EF> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.iter_mut().zip(rhs.iter()).for_each(|(x, y)| *x += y);
    }
}

impl<'a, F: Field, EF: AbstractExtensionField<F>> AddAssign<&'a DenseMultilinearExtension<F, EF>>
    for DenseMultilinearExtension<F, EF>
{
    #[inline]
    fn add_assign(&mut self, rhs: &'a DenseMultilinearExtension<F, EF>) {
        self.iter_mut().zip(rhs.iter()).for_each(|(x, y)| *x += y);
    }
}

impl<'a, F: Field, EF: AbstractExtensionField<F>>
    AddAssign<(EF, &'a DenseMultilinearExtension<F, EF>)> for DenseMultilinearExtension<F, EF>
{
    #[inline]
    fn add_assign(&mut self, (f, rhs): (EF, &'a DenseMultilinearExtension<F, EF>)) {
        self.iter_mut()
            .zip(rhs.iter())
            .for_each(|(x, y)| *x += f.mul(y));
    }
}

impl<'a, F: Field, EF: AbstractExtensionField<F>>
    AddAssign<(EF, &'a DenseMultilinearExtensionBase<F>)> for DenseMultilinearExtension<F, EF>
{
    #[inline]
    fn add_assign(&mut self, (f, rhs): (EF, &'a DenseMultilinearExtensionBase<F>)) {
        self.iter_mut()
            .zip(rhs.iter())
            .for_each(|(x, y)| *x += f * *y);
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> Neg for DenseMultilinearExtension<F, EF> {
    type Output = DenseMultilinearExtension<F, EF>;

    #[inline]
    fn neg(mut self) -> Self::Output {
        self.evaluations.iter_mut().for_each(|x| *x = -(*x));
        self
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> Sub for DenseMultilinearExtension<F, EF> {
    type Output = DenseMultilinearExtension<F, EF>;

    #[inline]
    fn sub(mut self, rhs: Self) -> Self {
        self.sub_assign(rhs);
        self
    }
}

impl<'a, F: Field, EF: AbstractExtensionField<F>> Sub<&'a DenseMultilinearExtension<F, EF>>
    for DenseMultilinearExtension<F, EF>
{
    type Output = DenseMultilinearExtension<F, EF>;

    #[inline]
    fn sub(mut self, rhs: &'a DenseMultilinearExtension<F, EF>) -> Self::Output {
        self.sub_assign(rhs);
        self
    }
}

impl<'a, 'b, F: Field, EF: AbstractExtensionField<F>> Sub<&'a DenseMultilinearExtension<F, EF>>
    for &'b DenseMultilinearExtension<F, EF>
{
    type Output = DenseMultilinearExtension<F, EF>;

    #[inline]
    fn sub(self, rhs: &'a DenseMultilinearExtension<F, EF>) -> Self::Output {
        // handle constant zero case
        if rhs.is_zero() {
            return self.clone();
        }
        if self.is_zero() {
            return rhs.clone();
        }
        assert_eq!(self.num_vars, rhs.num_vars);
        let result: Vec<EF> = self.iter().zip(rhs.iter()).map(|(&a, b)| a - b).collect();
        Self::Output::from_evaluations_vec(self.num_vars, result)
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> SubAssign for DenseMultilinearExtension<F, EF> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        self.iter_mut().zip(rhs.iter()).for_each(|(x, y)| *x -= y);
    }
}

impl<'a, F: Field, EF: AbstractExtensionField<F>> SubAssign<&'a DenseMultilinearExtension<F, EF>>
    for DenseMultilinearExtension<F, EF>
{
    #[inline]
    fn sub_assign(&mut self, rhs: &'a DenseMultilinearExtension<F, EF>) {
        self.iter_mut().zip(rhs.iter()).for_each(|(x, y)| *x -= y);
    }
}
