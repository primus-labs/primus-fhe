// It is derived from https://github.com/arkworks-rs/sumcheck.

use std::fmt::Debug;
use std::ops::{Add, AddAssign, Index, Neg, Sub, SubAssign};
use std::slice::{Iter, IterMut};

use num_traits::Zero;
use rand_distr::Distribution;

use crate::{DecomposableField, Field, FieldUniformSampler};

use super::MultilinearExtension;
use std::rc::Rc;

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
    #[inline]
    pub fn from_evaluations_slice(num_vars: usize, evaluations: &[F]) -> Self {
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
    #[inline]
    pub fn iter(&self) -> Iter<'_, F> {
        self.evaluations.iter()
    }

    /// Returns a mutable iterator that iterates over the evaluations over {0,1}^`num_vars`
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, F> {
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

impl<F: DecomposableField> DenseMultilinearExtension<F> {
    /// Decompose bits of each evaluation of the origianl MLE.
    /// The bit deomposition is only applied for power-of-two base.
    /// * base_len: the length of base, i.e. log_2(base)
    /// * bits_len: the lenth of decomposed bits
    ///
    /// The resulting decomposition bits are respectively wrapped into `Rc` struct, which can be more easilier added into the ListsOfProducts.
    #[inline]
    pub fn get_decomposed_mles(
        &self,
        base_len: u32,
        bits_len: u32,
    ) -> Vec<Rc<DenseMultilinearExtension<F>>> {
        let mut val = self.evaluations.clone();
        let mask = F::mask(base_len);

        let mut bits = Vec::with_capacity(bits_len as usize);

        // extract `base_len` bits as one "bit" at a time
        for _ in 0..bits_len {
            let mut bit = vec![F::zero(); self.evaluations.len()];
            bit.iter_mut().zip(val.iter_mut()).for_each(|(b_i, v_i)| {
                v_i.decompose_lsb_bits_at(b_i, mask, base_len);
            });
            bits.push(Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                self.num_vars,
                bit,
            )));
        }
        bits
    }
}

impl<F: Field> MultilinearExtension<F> for DenseMultilinearExtension<F> {
    type Point = [F];

    #[inline]
    fn num_vars(&self) -> usize {
        self.num_vars
    }

    #[inline]
    fn evaluate(&self, point: &Self::Point) -> F {
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
    fn to_evaluations(&self) -> Vec<F> {
        self.evaluations.to_vec()
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
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.evaluations[index]
    }
}

impl<F: Field> Debug for DenseMultilinearExtension<F> {
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

impl<F: Field> Zero for DenseMultilinearExtension<F> {
    #[inline]
    fn zero() -> Self {
        Self {
            num_vars: 0,
            evaluations: vec![F::zero()],
        }
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.num_vars == 0 && self.evaluations[0].is_zero()
    }
}

impl<F: Field> Add for DenseMultilinearExtension<F> {
    type Output = DenseMultilinearExtension<F>;
    #[inline]
    fn add(mut self, rhs: DenseMultilinearExtension<F>) -> Self {
        self.add_assign(rhs);
        self
    }
}

impl<'a, F: Field> Add<&'a DenseMultilinearExtension<F>> for DenseMultilinearExtension<F> {
    type Output = DenseMultilinearExtension<F>;
    #[inline]
    fn add(mut self, rhs: &'a DenseMultilinearExtension<F>) -> Self::Output {
        self.add_assign(rhs);
        self
    }
}

impl<'a, 'b, F: Field> Add<&'a DenseMultilinearExtension<F>> for &'b DenseMultilinearExtension<F> {
    type Output = DenseMultilinearExtension<F>;

    #[inline]
    fn add(self, rhs: &'a DenseMultilinearExtension<F>) -> Self::Output {
        // handle constant zero case
        if rhs.is_zero() {
            return self.clone();
        }
        if self.is_zero() {
            return rhs.clone();
        }
        assert_eq!(self.num_vars, rhs.num_vars);
        let result: Vec<F> = self.iter().zip(rhs.iter()).map(|(&a, b)| a + b).collect();
        Self::Output::from_evaluations_vec(self.num_vars, result)
    }
}

impl<F: Field> AddAssign for DenseMultilinearExtension<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.iter_mut().zip(rhs.iter()).for_each(|(x, y)| *x += y);
    }
}

impl<'a, F: Field> AddAssign<&'a DenseMultilinearExtension<F>> for DenseMultilinearExtension<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &'a DenseMultilinearExtension<F>) {
        self.iter_mut().zip(rhs.iter()).for_each(|(x, y)| *x += y);
    }
}

impl<'a, F: Field> AddAssign<(F, &'a DenseMultilinearExtension<F>)>
    for DenseMultilinearExtension<F>
{
    #[inline]
    fn add_assign(&mut self, (f, rhs): (F, &'a DenseMultilinearExtension<F>)) {
        self.iter_mut()
            .zip(rhs.iter())
            .for_each(|(x, y)| *x += f.mul(y));
    }
}

impl<'a, F: Field> AddAssign<(F, &'a Rc<DenseMultilinearExtension<F>>)>
    for DenseMultilinearExtension<F>
{
    #[inline]
    fn add_assign(&mut self, (f, rhs): (F, &'a Rc<DenseMultilinearExtension<F>>)) {
        self.iter_mut()
            .zip(rhs.iter())
            .for_each(|(x, y)| *x += f.mul(y));
    }
}

impl<F: Field> Neg for DenseMultilinearExtension<F> {
    type Output = DenseMultilinearExtension<F>;

    #[inline]
    fn neg(mut self) -> Self::Output {
        self.evaluations.iter_mut().for_each(|x| *x = -(*x));
        self
    }
}

impl<F: Field> Sub for DenseMultilinearExtension<F> {
    type Output = DenseMultilinearExtension<F>;

    #[inline]
    fn sub(mut self, rhs: Self) -> Self {
        self.sub_assign(rhs);
        self
    }
}

impl<'a, F: Field> Sub<&'a DenseMultilinearExtension<F>> for DenseMultilinearExtension<F> {
    type Output = DenseMultilinearExtension<F>;

    #[inline]
    fn sub(mut self, rhs: &'a DenseMultilinearExtension<F>) -> Self::Output {
        self.sub_assign(rhs);
        self
    }
}

impl<'a, 'b, F: Field> Sub<&'a DenseMultilinearExtension<F>> for &'b DenseMultilinearExtension<F> {
    type Output = DenseMultilinearExtension<F>;

    #[inline]
    fn sub(self, rhs: &'a DenseMultilinearExtension<F>) -> Self::Output {
        // handle constant zero case
        if rhs.is_zero() {
            return self.clone();
        }
        if self.is_zero() {
            return rhs.clone();
        }
        assert_eq!(self.num_vars, rhs.num_vars);
        let result: Vec<F> = self.iter().zip(rhs.iter()).map(|(&a, b)| a - b).collect();
        Self::Output::from_evaluations_vec(self.num_vars, result)
    }
}

impl<F: Field> SubAssign for DenseMultilinearExtension<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        self.iter_mut().zip(rhs.iter()).for_each(|(x, y)| *x -= y);
    }
}

impl<'a, F: Field> SubAssign<&'a DenseMultilinearExtension<F>> for DenseMultilinearExtension<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a DenseMultilinearExtension<F>) {
        self.iter_mut().zip(rhs.iter()).for_each(|(x, y)| *x -= y);
    }
}
