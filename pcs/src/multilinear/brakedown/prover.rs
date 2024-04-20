use super::*;

/// Prover of Brakedown PCS
#[derive(Debug, Clone, Default)]
pub struct BrakedownProver<F: Field> {
    /// brakedown pcs parameter
    pub pp: ProverParam<F>,

    /// brakedown pcs structures the coefficients of the polynomial in lagrange basis (or evaluations on the hypercube) as a matrix.
    ///
    /// while the entire matrix variable represents the vector containing the encoded matrix in a row-major manner,
    /// the first message_len columns compose the unencoded matrix since the code is systematic
    ///
    /// every codeword_len items is a codeword, and the first message_len items in every codeword_len items is its message
    matrix: Vec<F>,

    /// prover merklizes the columns of the matrix and stores the merkle tree
    merkle_tree: Vec<Hash>,

    /// polynomial commitment, which is the root of the merkle tree
    root: Hash,
}

impl<F: Field> BrakedownProver<F> {
    /// instansiate a brakedown prover from given prover parameters
    #[inline]
    pub fn new(pp: ProverParam<F>) -> Self {
        BrakedownProver {
            pp,
            ..Default::default()
        }
    }

    /// prover commits to given polynomial and returns its commitment
    #[inline]
    pub fn commit_poly(&mut self, poly: &Polynomial<F>) -> Hash {
        // input check
        assert!(poly.num_vars == self.pp.num_vars);

        // prepare the matrix to commit
        let message_len = self.pp.brakedown.message_len();
        let codeword_len = self.pp.brakedown.codeword_len();
        let mut matrix = vec![F::ZERO; self.pp.num_rows * codeword_len];

        // fill each row of the matrix with a message and
        // encode the message into the codeword
        matrix
            .chunks_exact_mut(codeword_len)
            .zip(poly.evaluations.chunks_exact(message_len))
            .for_each(|(row, eval)| {
                row[..message_len].copy_from_slice(eval);
                self.pp.brakedown.encode(row)
            });

        // hash each column of the matrix into a hash value
        let depth = codeword_len.next_power_of_two().ilog2() as usize;
        // prepare the container of the entire merkle tree, pushing the layers of merkle tree into this container from bottom to top
        let mut hashes: Vec<Hash> = vec![Hash::default(); (1 << (depth + 1)) - 1];
        let mut hasher = Sha3_256::new();
        hashes[..codeword_len]
            .iter_mut()
            .enumerate()
            .for_each(|(index, hash)| {
                matrix
                    .iter()
                    .skip(index)
                    .step_by(codeword_len)
                    .for_each(|item| hasher.update(item.to_string()));
                hash.copy_from_slice(hasher.finalize_reset().as_slice());
            });

        // merklize column hashes as leaves into a merkle tree
        let mut base = 0; // use base to index the start of the lower layer
        for depth in (1..=depth).rev() {
            // view the lower layer as the input and the upper layer as its output
            let input_len = 1 << depth;
            let output_len = input_len >> 1;
            let (inputs, outputs) =
                hashes[base..base + input_len + output_len].split_at_mut(input_len);
            // compute the output of the hash function given the input
            inputs
                .chunks_exact(2)
                .zip(outputs.iter_mut())
                .for_each(|(input, output)| {
                    hasher.update(input[0]);
                    hasher.update(input[1]);
                    output.copy_from_slice(hasher.finalize_reset().as_slice());
                });
            base += input_len;
        }

        // prover stores the results
        self.matrix = matrix;
        self.root = *hashes.last().unwrap();
        self.merkle_tree = hashes;

        self.root
    }

    /// prover answer the challenge by computing the product of the challenging vector and the committed matrix,
    /// while computing the product can also be viewed as a linear combination of rows of the matrix with challenging vector as the coefficients
    #[inline]
    pub fn answer_challenge(&self, challenge: &Vec<F>) -> Vec<F> {
        // rename variables for convenience
        let coeffs = challenge;
        let message_len = self.pp.brakedown.message_len();
        let codeword_len = self.pp.brakedown.codeword_len();

        // compute the answer as a linear combination
        let mut answer = vec![F::ZERO; message_len];
        self.matrix
            .chunks_exact(codeword_len)
            .zip(coeffs)
            .for_each(|(row, coeff)| {
                row.iter()
                    .take(message_len)
                    .enumerate()
                    .for_each(|(idx, item)| {
                        answer[idx] += (*item) * coeff;
                    })
            });
        answer
    }

    /// prover answers the query of columns of given indexes
    /// and gives merkle paths as the proof of its consistency with the commitment i.e. merkle root
    #[inline]
    pub fn answer_queries(&self, queries: &[usize]) -> (Vec<Vec<Hash>>, Vec<Vec<F>>) {
        // rename variables for convenience
        let codeword_len = self.pp.brakedown.codeword_len();
        let num_rows = self.pp.num_rows;

        // returns queried columns and their merkle paths
        (
            queries.iter().map(|idx| self.query_merkle(*idx)).collect(),
            queries
                .iter()
                .map(|idx| {
                    (0..num_rows)
                        .map(|row_idx| self.matrix[row_idx * codeword_len + idx])
                        .collect()
                })
                .collect(),
        )
    }

    /// return merkle paths of the leave i.e. committed column, of given index
    #[inline]
    fn query_merkle(&self, column_idx: usize) -> Vec<Hash> {
        let depth = self.pp.brakedown.codeword_len().next_power_of_two().ilog2() as usize;
        let mut base = 0;
        let mut merkle_path: Vec<Hash> = Vec::new();
        merkle_path.push(self.merkle_tree[column_idx]);
        (1..=depth).rev().enumerate().for_each(|(idx, depth)| {
            let layer_len = 1 << depth;
            let neighbour_idx = (column_idx >> idx) ^ 1;
            merkle_path.push(self.merkle_tree[base + neighbour_idx]);
            base += layer_len;
        });
        merkle_path
    }
}
