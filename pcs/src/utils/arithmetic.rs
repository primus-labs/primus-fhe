
use algebra::{Field, Random};

use std::{
    fmt::Debug,
    iter,
    collections::BTreeSet,
};

use rand::{distributions::Uniform, Rng, RngCore};


// a n x m sparse matrix with d nonzero elements in each row
#[derive(Clone, Copy, Debug)]
pub struct SparseMatrixDimension {
    pub n: usize,
    pub m: usize,
    pub d: usize,
}

impl SparseMatrixDimension {
    pub fn new(n: usize, m: usize, d: usize) -> Self {
        Self { n, m, d }
    }
}

#[derive(Clone, Debug)]
pub struct SparseMatrix<F> {
    pub dimension: SparseMatrixDimension,
    pub cells: Vec<(usize, F)>,
}


impl<F: Field + Random> SparseMatrix<F> {
    // create a random sparse matrix in a row major manner
    pub fn random(dimension: SparseMatrixDimension, mut rng: impl RngCore) -> Self {
        let cells = iter::repeat_with(|| {
            let mut row = BTreeSet::<usize>::new();
            // sample which indexes of this row are nonempty
            (&mut rng)
                .sample_iter(Uniform::new(0, dimension.m))
                .filter(|index| row.insert(*index))
                .take(dimension.d)
                .count();
            // sample the random field elements at these indexes
            row
                .into_iter()
                .map(|index| (index, rng.sample(F::uniform_sampler())))
                .collect::<Vec<(usize, F)>>()
        })
        .take(dimension.n)
        .flatten()
        .collect();
        Self { dimension, cells }
    }

    // provide each row of the sparse matrix
    pub fn rows(&self) -> impl Iterator<Item = &[(usize, F)]> {
        self.cells.chunks(self.dimension.d)
    }

    // store the (m x 1) dot product of a (1 x n) vector and a (n x m) matrix into target
    pub fn dot_into(&self, vector: &[F], mut target: impl AsMut<[F]>) {
        let target = target.as_mut();
        assert_eq!(self.dimension.n, vector.len());
        assert_eq!(self.dimension.m, target.len());

        // t = v * M
        // t = \sum_{i=1}^{n} v_i * M_i
        // t is the linear combination of rows of M with v as the coefficients
        self.rows().zip(vector.iter()).for_each(|(cells, item)| {
            cells.iter().for_each(|(column, coeff)| {
                target[*column] += *item * coeff;
            })
        });
    }

    pub fn dot(&self, array: &[F]) -> Vec<F> {
        let mut target = vec![F::ZERO; self.dimension.m];
        self.dot_into(array, &mut target);
        target
    }
}

// compute the entropy
// H(p) = -p \log_2(p) - (1 - p) \log_2(1 - p)
pub fn h(p: f64) -> f64 {
    assert!(0f64 < p && p < 1f64);
    let one_minus_p = 1f64 - p;
    -p * p.log2() - one_minus_p * one_minus_p.log2()
}

pub fn ceil(v: f64) -> usize {
    v.ceil() as usize
}

pub fn div_ceil(dividend: usize, divisor: usize) -> usize {
    dividend.div_ceil(divisor)
}
