use crate::utils::code::{BrakedownCode, BrakedownCodeSpec, LinearCode};
use algebra::{DenseMultilinearExtension, Field, FieldUniformSampler};
use rand::{distributions::Uniform, Rng, RngCore};
use sha3::{Digest, Sha3_256};
use std::marker::PhantomData;

/// Parameters of Brakedown Multilinear Polynomial Commitment Scheme
///
/// prover's pcs parameters and verifier's pcs parameters are the same for brakedown pcs
#[derive(Clone, Debug, Default)]
pub struct BrakedownParam<F: Field> {
    /// the number of the variables of the multilinear polynomial
    pub num_vars: usize,
    /// the number of the rows of the evaluation matrix of the multilinear polynomial
    pub num_rows: usize,
    /// the linear code in brakedown pcs
    pub brakedown: BrakedownCode<F>,
}

type ProverParam<F> = BrakedownParam<F>;
type VerifierParam<F> = BrakedownParam<F>;
type Polynomial<F> = DenseMultilinearExtension<F>;

/// 256bit hash value, whose length is determined by the security paranter
type Hash = [u8; 32];

/// Protocol of Brakedown PCS
#[derive(Debug, Clone, Default)]
pub struct BrakedownProtocol<F: Field> {
    field: PhantomData<F>,
}

impl<F: Field> BrakedownProtocol<F> {
    /// transparent setup to reach a consensus of
    /// field of the polynomial,
    /// variable number of the polynomial,
    /// message length of the code (which enables variant overhead tradeoffs),
    /// code specification ( whic requires the same randomness for prover and verifier to generate the code)
    pub fn setup(
        num_vars: usize,
        message_len: usize,
        spec: BrakedownCodeSpec,
        rng: impl RngCore,
    ) -> (ProverParam<F>, VerifierParam<F>) {
        // input check
        assert!(1 << num_vars >= message_len);

        // create the pcs parameter
        let brakedown: BrakedownCode<F> = BrakedownCode::new(spec, message_len, rng);
        let param = BrakedownParam {
            num_vars,
            num_rows: (1 << num_vars) / brakedown.message_len(),
            brakedown,
        };
        let pp = param.clone();
        let vp = param;
        (pp, vp)
    }
}

/// Prover of Brakedown PCS
#[derive(Debug, Clone, Default)]
pub struct BrakedownProver<F: Field> {
    /// brakedown pcs parameter
    pp: ProverParam<F>,

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

/// Verifier of Brakedown PCS
#[derive(Debug, Clone, Default)]
pub struct BrakedownVerifier<F: Field, R: RngCore + Default> {
    /// brakedown pcs parameter
    vp: VerifierParam<F>,

    /// verifier challenges prover using this source of randomness
    /// which can be substituted by Fiat-Shamir transformation
    randomness: R,

    /// commitment of the polynomia i.e. the merkle root
    root: Hash,

    /// chanllenge,
    /// either a random vector or
    /// a tensor of the point that the verifier wants to evaluate at
    challenge: Vec<F>,

    /// answer of the chanllenge
    answer: Vec<F>,

    /// indexes of queries
    queries: Vec<usize>,

    /// decompose a point into two tensors,
    /// store one tensor in the challenge and
    /// store the other one in this residual tensor
    residual_tensor: Vec<F>,
}

impl<F: Field, R: RngCore + Default> BrakedownVerifier<F, R> {
    /// create a verifier
    #[inline]
    pub fn new(vp: VerifierParam<F>, randomness: R) -> Self {
        BrakedownVerifier {
            vp,
            randomness,
            ..Default::default()
        }
    }

    /// receive the commitment i.e. the merkle root
    #[inline]
    pub fn receive_root(&mut self, root: Hash) {
        self.root = root;
    }

    /// generate a random challenge
    #[inline]
    pub fn random_challenge(&mut self) -> &Vec<F> {
        let field_distr: FieldUniformSampler<F> = FieldUniformSampler::new();
        self.challenge = (&mut self.randomness)
            .sample_iter(field_distr)
            .take(self.vp.num_rows)
            .collect();
        &self.challenge
    }

    /// generate random queries
    #[inline]
    pub fn random_queries(&mut self) -> &Vec<usize> {
        // rename variables for convenience
        let num_queries = self.vp.brakedown.num_queries();
        let codeword_len = self.vp.brakedown.codeword_len();

        // generate a random set of queries or a set of full queries
        if num_queries < codeword_len {
            let index_distr: Uniform<usize> = Uniform::new(0, self.vp.brakedown.codeword_len());
            self.queries = (&mut self.randomness)
                .sample_iter(index_distr)
                .take(num_queries)
                .collect();
        } else {
            // in toy examples, num_queries > codeword_len may happen
            // if so, shorten the queries into queries of all columns
            self.queries = (0..codeword_len).collect::<Vec<usize>>();
        }
        &self.queries
    }

    /// receive the answer which is a message, and then
    /// encode the answer into a codeword
    #[inline]
    pub fn receive_answer(&mut self, mut answer: Vec<F>) {
        // input check
        assert!(answer.len() == self.vp.brakedown.message_len());

        // encode the answer
        answer.resize(self.vp.brakedown.codeword_len(), F::ZERO);
        self.vp.brakedown.encode(&mut answer);
        self.answer = answer;
    }

    /// check the answer
    #[inline]
    pub fn check_answer(&mut self, merkle_paths: Vec<Vec<Hash>>, columns: Vec<Vec<F>>) {
        // input check
        assert!(self.challenge.len() == self.vp.num_rows);
        assert!(columns.len() == self.queries.len());
        assert!(merkle_paths.len() == self.queries.len());

        // check merkle
        self.check_merkle(&merkle_paths, &columns);
        // check consistency
        self.check_consistency(&columns);
    }

    /// check the hash of column is the same as the merkle leave
    /// check the merkle path is consistent with the merkle root
    #[inline]
    fn check_merkle(&self, merkle_paths: &Vec<Vec<Hash>>, columns: &[Vec<F>]) {
        let mut hasher = Sha3_256::new();
        columns
            .iter()
            .zip(merkle_paths)
            .zip(&self.queries)
            .for_each(|((column, hashes), column_idx)| {
                // check the hash of column is the same as the merkle leave
                column
                    .iter()
                    .for_each(|item| hasher.update(item.to_string()));
                let mut leaf = Hash::default();
                leaf.copy_from_slice(hasher.finalize_reset().as_slice());
                assert!(leaf == hashes[0]);

                // check the merkle path is consistent with the merkle root
                let root = hashes[1..]
                    .iter()
                    .enumerate()
                    .fold(leaf, |acc, (idx, hash)| {
                        if (column_idx >> idx) & 1 == 0 {
                            hasher.update(acc);
                            hasher.update(hash);
                        } else {
                            hasher.update(hash);
                            hasher.update(acc);
                        }
                        let mut hash = Hash::default();
                        hash.copy_from_slice(hasher.finalize_reset().as_slice());
                        hash
                    });
                assert!(root == self.root);
            });
    }

    /// check the consistency of entry of answers with the product of challenge and column, at the given indexes
    #[inline]
    fn check_consistency(&self, columns: &[Vec<F>]) {
        columns.iter().zip(&self.queries).for_each(|(column, idx)| {
            assert!(column.len() == self.vp.num_rows);
            let product = column
                .iter()
                .zip(&self.challenge)
                .map(|(x0, x1)| *x0 * x1)
                .fold(F::ZERO, |acc, x| acc + x);
            assert!(product == self.answer[*idx]);
        })
    }

    /// decompose a evaluation point x into two tensor q1, q2 that
    /// f(x) = q1 M q2 where M is the committed matrix
    #[inline]
    pub fn tensor_decompose(&mut self, point: &Vec<F>) -> Vec<F> {
        let left_point_len = self.vp.num_rows.ilog2() as usize;
        let right_point_len = self.vp.brakedown.message_len().ilog2() as usize;
        assert!(left_point_len + right_point_len == point.len());

        self.challenge = Self::lagrange_basis(&point[left_point_len..]);
        self.residual_tensor = Self::lagrange_basis(&point[..left_point_len]);

        assert!(self.challenge.len() == self.vp.num_rows);
        assert!(self.residual_tensor.len() == self.vp.brakedown.message_len());

        self.challenge.clone()
    }

    /// compute the lagrange basis of a given point (which is a series of point of one dimension)
    #[inline]
    fn lagrange_basis(points: &[F]) -> Vec<F> {
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

    /// compute the residual produc
    pub fn residual_product(&self) -> F {
        self.answer
            .iter()
            .zip(&self.residual_tensor)
            .map(|(x0, x1)| *x0 * x1)
            .fold(F::ZERO, |acc, add| acc + add)
    }
}
