use super::*;

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
    pub fn receive_root(&mut self, root: &Hash) {
        self.root = *root;
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
    pub fn receive_answer(&mut self, answer: &Vec<F>) {
        // input check
        assert!(answer.len() == self.vp.brakedown.message_len());
        self.answer = answer.clone();

        // encode the answer
        self.answer
            .resize(self.vp.brakedown.codeword_len(), F::ZERO);
        self.vp.brakedown.encode(&mut self.answer);
    }

    /// check the answer
    #[inline]
    pub fn check_answer(&mut self, merkle_paths: &Vec<Vec<Hash>>, columns: &Vec<Vec<F>>) -> bool {
        // input check
        assert!(self.challenge.len() == self.vp.num_rows);
        assert!(columns.len() == self.queries.len());
        assert!(merkle_paths.len() == self.queries.len());

        // check merkle
        let check_merkel = self.check_merkle(merkle_paths, columns);
        // check consistency
        let check_consistency = self.check_consistency(columns);
        check_merkel && check_consistency
    }

    /// check the hash of column is the same as the merkle leave
    /// check the merkle path is consistent with the merkle root
    #[inline]
    fn check_merkle(&self, merkle_paths: &Vec<Vec<Hash>>, columns: &[Vec<F>]) -> bool {
        let mut check = true;
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
                if root != self.root {
                    check = false
                }
            });
        check
    }

    /// check the consistency of entry of answers with the product of challenge and column, at the given indexes
    #[inline]
    fn check_consistency(&self, columns: &[Vec<F>]) -> bool {
        let mut check = true;
        columns.iter().zip(&self.queries).for_each(|(column, idx)| {
            assert!(column.len() == self.vp.num_rows);
            let product = column
                .iter()
                .zip(&self.challenge)
                .map(|(x0, x1)| *x0 * x1)
                .fold(F::ZERO, |acc, x| acc + x);
            if product != self.answer[*idx] {
                check = false
            };
        });
        check
    }

    /// decompose a evaluation point x into two tensor q1, q2 that
    /// f(x) = q1 M q2 where M is the committed matrix
    #[inline]
    pub fn tensor_decompose(&mut self, point: &Vec<F>) -> Vec<F> {
        let left_point_len = self.vp.num_rows.ilog2() as usize;
        let right_point_len = self.vp.brakedown.message_len().ilog2() as usize;
        assert!(left_point_len + right_point_len == point.len());

        self.challenge = Self::lagrange_basis(&point[right_point_len..]);

        self.residual_tensor = Self::lagrange_basis(&point[..right_point_len]);

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
