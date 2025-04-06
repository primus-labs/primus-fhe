use algebra::{Field, U64FieldEval};

pub struct Matrix {
    pub data: Vec<Vec<u64>>,
}
impl Default for Matrix {
    fn default() -> Self {
        Matrix { data: Vec::new() }
    }
}

impl Matrix {
    pub fn new(rows: usize, cols: usize) -> Self {
        let data = vec![vec![0; cols]; rows];
        Matrix { data }
    }

    pub fn from_vec(data: Vec<Vec<u64>>) -> Self {
        Matrix { data }
    }

    pub fn transpose(&self) -> Self {
        let mut transposed = Matrix::new(self.data[0].len(), self.data.len());
        for i in 0..self.data.len() {
            for j in 0..self.data[i].len() {
                transposed.data[j][i] = self.data[i][j];
            }
        }
        transposed
    }

    pub fn sub_matrix(
        matrix: &Matrix,
        start_row: usize,
        end_row: usize,
        start_col: usize,
        end_col: usize,
    ) -> Matrix {
        let mut sub_matrix = Matrix::new(end_row - start_row, end_col - start_col);
        for i in start_row..end_row {
            for j in start_col..end_col {
                sub_matrix.data[i - start_row][j - start_col] = matrix.data[i][j];
            }
        }
        sub_matrix
    }

    pub fn transposed_sub_matrix(
        matrix: &Matrix,
        start_row: usize,
        end_row: usize,
        start_col: usize,
        end_col: usize,
    ) -> Matrix {
        let mut sub_matrix = Matrix::new(end_col - start_col, end_row - start_row);
        for i in start_row..end_row {
            for j in start_col..end_col {
                sub_matrix.data[j - start_col][i - start_row] = matrix.data[i][j];
            }
        }
        sub_matrix
    }

    pub fn transposed_sub_matrix_with_data(
        matrix: &[Vec<u64>],
        start_row: usize,
        end_row: usize,
        start_col: usize,
        end_col: usize,
    ) -> Matrix {
        let mut sub_matrix = Matrix::new(end_col - start_col, end_row - start_row);
        for i in start_row..end_row {
            for j in start_col..end_col {
                sub_matrix.data[j - start_col][i - start_row] = matrix[i][j];
            }
        }
        sub_matrix
    }

    pub fn multiply<const P: u64>(&self, other: &Matrix) -> Matrix {
        let mut result = Matrix::new(self.data.len(), other.data[0].len());
        for i in 0..self.data.len() {
            for k in 0..self.data[i].len() {
                for j in 0..other.data[0].len() {
                    result.data[i][j] = <U64FieldEval<P>>::mul_add(
                        self.data[i][k],
                        other.data[k][j],
                        result.data[i][j],
                    );
                }
            }
        }
        result
    }

    pub fn multiply_with_data<const P: u64>(&self, other: &[Vec<u64>]) -> Matrix {
        let mut result = Matrix::new(self.data.len(), other[0].len());
        for i in 0..self.data.len() {
            for k in 0..self.data[i].len() {
                for j in 0..other[0].len() {
                    result.data[i][j] =
                        <U64FieldEval<P>>::mul_add(self.data[i][k], other[k][j], result.data[i][j]);
                }
            }
        }
        result
    }

    pub fn multiply_with_vec<const P: u64>(&self, other: &[u64]) -> Vec<u64> {
        self.data
            .iter()
            .map(|row| <U64FieldEval<P>>::dot_product(row, other))
            .collect()
    }
}
