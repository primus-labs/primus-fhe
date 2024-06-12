use algebra::{Field, FieldUniformSampler};

use std::{collections::BTreeSet, fmt::Debug, iter};

use rand::{distributions::Uniform, CryptoRng, Rng};

/// a dimension that specifies a sparse matrix of row_num = n, column_num = m, with d nonzero elements in each row
#[derive(Clone, Copy, Debug)]
pub struct SparseMatrixDimension {
    /// the number of rows of the sparse matrix
    pub row: usize,
    /// the number of columns of the sparse matrix
    pub column: usize,
    /// the number of nonzero elements in each row of the sparse matrix
    pub nonzero: usize,
}

impl SparseMatrixDimension {
    /// create an instance of SparseMatrixDimension
    #[inline]
    pub fn new(row: usize, column: usize, nonzero: usize) -> Self {
        //println!("row {}", row_num);
        //println!("column {}", column_num);
        //println!("nonzero {}", nonzero_num);
        Self {
            row: row,
            column: column,
            nonzero: nonzero,
        }
    }
}

/// SparseMatrix
#[derive(Clone, Debug)]
pub struct SparseMatrix<F> {
    /// the dimension that specifies the shape of this sparse matrix
    pub dimension: SparseMatrixDimension,
    /// the elements of sparse matrix in a row major manner
    pub cells: Vec<(usize, F)>,
}

impl<F: Field> SparseMatrix<F> {
    /// create a random sparse matrix in a row major manner, given the dimension and randomness
    pub fn random(dimension: SparseMatrixDimension, mut rng: impl Rng + CryptoRng) -> Self {
        let index_distr: Uniform<usize> = Uniform::new(0, dimension.column);
        let field_distr: FieldUniformSampler<F> = FieldUniformSampler::new();
        let mut row = BTreeSet::<usize>::new();
        let cells = iter::repeat_with(|| {
            // sample which indexes of this row are nonempty
            row.clear();
            (&mut rng)
                .sample_iter(index_distr)
                .filter(|index| row.insert(*index))
                .take(dimension.nonzero)
                .count();
            // sample the random field elements at these indexes
            row.iter()
                .map(|index| (*index, rng.sample(field_distr)))
                .collect::<Vec<(usize, F)>>()
        })
        .take(dimension.nonzero)
        .flatten()
        .collect();
        Self { dimension, cells }
    }

    /// provide each row of the sparse matrix
    #[inline]
    fn rows(&self) -> impl Iterator<Item = &[(usize, F)]> {
        self.cells.chunks_exact(self.dimension.nonzero)
    }

    /// store the (1 x m) dot product of a (1 x n) vector and this (n x m) matrix into target
    /// target should keep clean (all zeros) before calling dot_into()
    #[inline]
    pub fn multiply_vector(&self, vector: &[F], target: &mut[F]) {
        assert_eq!(self.dimension.row, vector.len());
        assert_eq!(self.dimension.column, target.len());

        // t = v * M
        // t = \sum_{i=1}^{n} v_i * M_i
        // t is the linear combination of rows of M with v as the coefficients
        self.rows().zip(vector.iter()).for_each(|(cells, item)| {
            cells.iter().for_each(|(column, coeff)| {
                target[*column] += *item * coeff;
            })
        });

        println!("input\n {:?}\n", vector);
        println!("output\n {:?}\n\n", target);
    }

/// return the (1 x m) dot product of a (1 x n) vector and this (n x m) matrix
    #[inline]
    pub fn dot(&self, array: &[F]) -> Vec<F> {
        let mut target = vec![F::ZERO; self.dimension.column];
        self.multiply_vector(array, &mut target);
        target
    }
}

/// compute the entropy: H(p) = -p \log_2(p) - (1 - p) \log_2(1 - p)
#[inline]
pub fn entropy(p: f64) -> f64 {
    assert!(0f64 < p && p < 1f64);
    let one_minus_p = 1f64 - p;
    -p * p.log2() - one_minus_p * one_minus_p.log2()
}

/// compute the ceil
#[inline]
pub fn ceil(v: f64) -> usize {
    v.ceil() as usize
}

/// compute the division and take the ceil
#[inline]
pub fn div_ceil(dividend: usize, divisor: usize) -> usize {
    let d = dividend / divisor;
    let r = dividend % divisor;
    if r > 0 {
        d + 1
    } else {
        d
    }
}


/// compute whether the input is a power of two
#[inline]
pub fn is_power_of_two(x: usize) -> bool {
    x != 0 && (x & (x - 1)) == 0
}

/// compute the lagrange basis of a given point (which is a series of point of one dimension)
#[inline]
pub fn lagrange_basis<F: Field>(points: &[F]) -> Vec<F> {
    let mut basis = vec![F::ONE];
    points.iter().for_each(|point| {
        basis.extend(
            basis
                .iter()
                .map(|x| *x * (F::ONE - point))
                .collect::<Vec<F>>(),
        );
        let prev_len = basis.len() >> 1;
        basis.iter_mut().take(prev_len).for_each(|x| *x *= point);
    });
    assert!(basis.len() == 1 << points.len());

    basis.reverse();
    basis
}
