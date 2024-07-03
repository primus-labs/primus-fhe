use std::slice::{Iter, IterMut};

use crate::Field;

/// sparse polynomial
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SparsePolynomial<F: Field> {
    /// The evaluation over {0,1}^`num_vars`
    pub evaluations: Vec<(usize, F)>,
    /// Number of variables
    pub num_vars: usize,
}

impl<F: Field> SparsePolynomial<F> {
    /// Construct a new polynomial from a list of evaluations where the index
    /// represents a point in {0,1}^`num_vars` in little endian form. For
    /// example, `0b1011` represents `P(1,1,0,1)`
    #[inline]
    pub fn from_evaluations_slice(num_vars: usize, evaluations: &[(usize, F)]) -> Self {
        assert!(
            evaluations.len() <= 1 << num_vars,
            "The size of evaluations should be no more than2^num_vars."
        );
        Self::from_evaluations_vec(num_vars, evaluations.to_vec())
    }

    /// Construct a new polynomial from a list of evaluations where the index
    /// represents a point in {0,1}^`num_vars` in little endian form. For
    /// example, `0b1011` represents `P(1,1,0,1)`
    #[inline]
    pub fn from_evaluations_vec(num_vars: usize, evaluations: Vec<(usize, F)>) -> Self {
        assert!(
            evaluations.len() <= 1 << num_vars,
            "The size of evaluations should be no more than2^num_vars."
        );
        Self {
            num_vars,
            evaluations,
        }
    }

    /// Returns an iterator that iterates over the evaluations over {0,1}^`num_vars`
    #[inline]
    pub fn iter(&self) -> Iter<'_, (usize, F)> {
        self.evaluations.iter()
    }

    /// Returns a mutable iterator that iterates over the evaluations over {0,1}^`num_vars`
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, (usize, F)> {
        self.evaluations.iter_mut()
    }
}
