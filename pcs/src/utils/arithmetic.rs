use algebra::{AbstractExtensionField, Field, FieldUniformSampler};
use serde::{Deserialize, Serialize};

use std::{collections::BTreeSet, fmt::Debug, iter};

use rand::{distributions::Uniform, CryptoRng, Rng};

/// Define the dimension that specifies a sparse matrix.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct SparseMatrixDimension {
    /// the number of rows of the sparse matrix
    pub num_row: usize,
    /// the number of columns of the sparse matrix
    pub num_col: usize,
    /// the number of nonzero elements in each row of the sparse matrix
    pub num_nonzero: usize,
}

impl SparseMatrixDimension {
    /// create an instance of SparseMatrixDimension
    ///
    /// # Arguments.
    ///
    /// * `num_row` - the number of rows.
    /// * `num_col` - the number of columns.
    /// * `num_nonzero` - the number of non-zero elements.
    #[inline]
    pub fn new(num_row: usize, num_col: usize, num_nonzero: usize) -> Self {
        Self {
            num_row,
            num_col,
            num_nonzero,
        }
    }
}

/// Define the struct of SparseMatrix
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparseMatrix<F> {
    /// The dimension that specifies the shape of this sparse matrix
    pub dimension: SparseMatrixDimension,
    /// The elements of sparse matrix in a row major manner
    pub cells: Vec<(usize, F)>,
}

impl<F: Field> SparseMatrix<F> {
    /// Generate a random sparse matrix.
    ///
    /// # Arguments.
    ///
    /// * `dimension` - The dimension of the sparse matrix.
    /// * `rng` - The randomness generator.
    pub fn random(dimension: SparseMatrixDimension, rng: &mut (impl Rng + CryptoRng)) -> Self {
        let index_distr: Uniform<usize> = Uniform::new(0, dimension.num_col);
        let field_distr: FieldUniformSampler<F> = FieldUniformSampler::new();
        let mut row = BTreeSet::<usize>::new();
        let cells = iter::repeat_with(|| {
            // sample which indexes of this row are nonempty
            row.clear();
            rng.sample_iter(index_distr)
                .filter(|index| row.insert(*index))
                .take(dimension.num_nonzero)
                .count();
            // sample the random field elements at these indexes
            row.iter()
                .map(|index| (*index, rng.sample(field_distr)))
                .collect::<Vec<(usize, F)>>()
        })
        .take(dimension.num_row)
        .flatten()
        .collect();
        Self { dimension, cells }
    }

    /// Return the rows of the sparse matrix.
    #[inline]
    fn rows(&self) -> impl Iterator<Item = &[(usize, F)]> {
        self.cells.chunks_exact(self.dimension.num_nonzero)
    }

    /// Compute multiplication-then-addition.
    ///
    /// # Arguments
    ///
    /// * `vector` - The vector that are multiplied by the sparce matrix.
    /// * `target` - The vector that are added to the multiplication, and stores the result.
    #[inline]
    pub fn add_multiplied_vector(&self, vector: &[F], target: &mut [F]) {
        assert_eq!(self.dimension.num_row, vector.len());
        assert_eq!(self.dimension.num_col, target.len());

        // t = v * M
        // t = \sum_{i=1}^{n} v_i * M_i
        // t is the linear combination of rows of M with v as the coefficients
        self.rows().zip(vector.iter()).for_each(|(cells, item)| {
            cells.iter().for_each(|(column, coeff)| {
                target[*column] += *item * coeff;
            })
        });
    }

    /// Compute multiplication-then-addition.
    ///
    /// # Arguments
    ///
    /// * `vector` - The vector in the extension field that are multiplied by the sparce matrix.
    /// * `target` - The vector in the extension field that are added to the multiplication, and stores the result.
    #[inline]
    pub fn add_multiplied_vector_ext<EF: AbstractExtensionField<F>>(
        &self,
        vector: &[EF],
        target: &mut [EF],
    ) {
        assert_eq!(self.dimension.num_row, vector.len());
        assert_eq!(self.dimension.num_col, target.len());

        // t = v * M
        // t = \sum_{i=1}^{n} v_i * M_i
        // t is the linear combination of rows of M with v as the coefficients
        self.rows().zip(vector.iter()).for_each(|(cells, item)| {
            cells.iter().for_each(|(column, coeff)| {
                target[*column] += *item * (*coeff);
            })
        });
    }

    /// The dot product of a vector and the sparse matrix.
    ///
    /// # Arguments
    ///
    /// * `array` - The vector that are multiplied by the sparse matrix.
    #[inline]
    pub fn dot(&self, array: &[F]) -> Vec<F> {
        let mut target = vec![F::zero(); self.dimension.num_col];
        self.add_multiplied_vector(array, &mut target);
        target
    }
}

/// Compute the entropy: H(p) = -p \log_2(p) - (1 - p) \log_2(1 - p)
#[inline]
pub fn entropy(p: f64) -> f64 {
    assert!(0f64 < p && p < 1f64);
    let one_minus_p = 1f64 - p;
    -p * p.log2() - one_minus_p * one_minus_p.log2()
}

/// Compute the ceil
#[inline]
pub fn ceil(v: f64) -> usize {
    v.ceil() as usize
}

/// Compute the division and take the ceil
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

/// Compute the lagrange basis of a given point (which is a series of point of one dimension)
#[inline]
pub fn lagrange_basis<F: Field, EF: AbstractExtensionField<F>>(points: &[EF]) -> Vec<EF> {
    let mut basis = vec![EF::one()];
    points.iter().for_each(|point| {
        basis.extend(basis.iter().map(|x| *x * point).collect::<Vec<EF>>());
        let prev_len = basis.len() >> 1;
        basis
            .iter_mut()
            .take(prev_len)
            .for_each(|x| *x *= EF::one() - point);
    });
    assert!(basis.len() == 1 << points.len());

    basis
}
