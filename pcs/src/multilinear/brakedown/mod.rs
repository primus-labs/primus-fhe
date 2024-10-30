//! Implementation of Brakedown PCS, note that it is optimized for unformly random points, as described in [DP23](https://eprint.iacr.org/2023/630.pdf)

mod data_structure;

pub use data_structure::{
    BrakedownCommitmentState, BrakedownOpenProof, BrakedownOpenProofGeneral, BrakedownParams,
    BrakedownPolyCommitment,
};

use algebra::{
    utils::{Block, Prg, Transcript},
    AbstractExtensionField, DenseMultilinearExtension, Field,
};
use itertools::{izip, Itertools};
use rand::SeedableRng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, mem::transmute};

use crate::{
    utils::{
        arithmetic::lagrange_basis,
        code::{LinearCode, LinearCodeSpec},
        hash::Hash,
        merkle_tree::MerkleTree,
    },
    PolynomialCommitmentScheme,
};

/// The security parameter
pub const BRAKEDOWN_SECURITY_BIT: usize = 128;

/// The PCS struct for Brakedown.
#[derive(Debug, Clone)]
pub struct BrakedownPCS<F, H, C, S, EF>(PhantomData<(F, H, C, S, EF)>)
where
    F: Field,
    H: Hash + Sync + Send,
    C: LinearCode<F>,
    S: LinearCodeSpec<F, Code = C>,
    EF: AbstractExtensionField<F>;

impl<F, H, C, S, EF> BrakedownPCS<F, H, C, S, EF>
where
    F: Field,
    H: Hash + Sync + Send,
    C: LinearCode<F>,
    S: LinearCodeSpec<F, Code = C>,
    EF: AbstractExtensionField<F>,
{
    /// Prover answers the challenge by computing the product of the challenge vector
    /// and the committed matrix.
    /// The computation of the product can be viewed as a linear combination of rows
    /// of the matrix with challenge vector as the coefficients.
    fn answer_challenge(
        pp: &BrakedownParams<F, EF, C>,
        challenge: &[EF],
        state: &BrakedownCommitmentState<F, H>,
    ) -> Vec<EF> {
        assert_eq!(challenge.len(), pp.num_rows());
        let num_cols = pp.code().message_len();
        let codeword_len = pp.code().codeword_len();

        // Compute the answer as a linear combination.
        let mut answer = vec![EF::zero(); num_cols];
        state
            .matrix
            .chunks_exact(codeword_len)
            .zip(challenge)
            .for_each(|(row, coeff)| {
                row.iter()
                    .take(num_cols)
                    .enumerate()
                    .for_each(|(idx, item)| {
                        answer[idx] += *coeff * *item;
                    })
            });
        answer
    }

    /// Prover answers the challenge by computing the product of the challenge vector
    /// and the committed matrix.
    /// The computation of the product can be viewed as a linear combination of rows
    /// of the matrix with challenge vector as the coefficients.
    fn answer_challenge_ext(
        pp: &BrakedownParams<F, EF, C>,
        challenge: &[EF],
        state: &BrakedownCommitmentState<EF, H>,
    ) -> Vec<EF> {
        assert_eq!(challenge.len(), pp.num_rows());
        let num_cols = pp.code().message_len();
        let codeword_len = pp.code().codeword_len();

        // Compute the answer as a linear combination.
        let mut answer = vec![EF::zero(); num_cols];
        state
            .matrix
            .chunks_exact(codeword_len)
            .zip(challenge)
            .for_each(|(row, coeff)| {
                row.iter()
                    .take(num_cols)
                    .enumerate()
                    .for_each(|(idx, item)| {
                        answer[idx] += *coeff * *item;
                    })
            });
        answer
    }

    /// Prover answers the query of columns of given indices
    /// and gives merkle paths as the proof of its consistency with the merkle root.
    fn answer_queries(
        pp: &BrakedownParams<F, EF, C>,
        queries: &[usize],
        state: &BrakedownCommitmentState<F, H>,
    ) -> (Vec<H::Output>, Vec<F>) {
        let codeword_len = pp.code().codeword_len();
        let num_rows = pp.num_rows();

        // Compute the merkle proofs
        let merkle_proof = queries
            .iter()
            .flat_map(|idx| state.merkle_tree.query(*idx))
            .collect();

        // Collect the columns as part of the answers.
        let columns = queries
            .iter()
            .flat_map(|idx| {
                (0..num_rows)
                    .map(|row_idx| state.matrix[row_idx * codeword_len + idx])
                    .collect_vec()
            })
            .collect();
        (merkle_proof, columns)
    }

    /// Prover answers the query of columns of given indices
    /// and gives merkle paths as the proof of its consistency with the merkle root.
    fn answer_queries_ext(
        pp: &BrakedownParams<F, EF, C>,
        queries: &[usize],
        state: &BrakedownCommitmentState<EF, H>,
    ) -> (Vec<H::Output>, Vec<EF>) {
        let codeword_len = pp.code().codeword_len();
        let num_rows = pp.num_rows();

        // Compute the merkle proofs
        let merkle_proof = queries
            .iter()
            .flat_map(|idx| state.merkle_tree.query(*idx))
            .collect();

        // Collect the columns as part of the answers.
        let columns = queries
            .iter()
            .flat_map(|idx| {
                (0..num_rows)
                    .map(|row_idx| state.matrix[row_idx * codeword_len + idx])
                    .collect_vec()
            })
            .collect();
        (merkle_proof, columns)
    }
    /// Decompose an evaluation of point x into two tensors q1, q2 such that
    /// f(x) = q1 * M * q2 where M is the committed matrix.
    fn tensor_decompose(pp: &BrakedownParams<F, EF, C>, point: &[EF]) -> (Vec<EF>, Vec<EF>) {
        let left_point_len = pp.num_rows().ilog2() as usize;
        let right_point_len = pp.code().message_len().ilog2() as usize;
        assert_eq!(left_point_len + right_point_len, point.len());

        let challenge = lagrange_basis(&point[right_point_len..]);

        let residual_tensor = lagrange_basis(&point[..right_point_len]);

        assert_eq!(challenge.len(), pp.num_rows());
        assert_eq!(residual_tensor.len(), pp.code().message_len());

        (challenge, residual_tensor)
    }

    /// Generate tensor from points.
    fn tensor_from_points(pp: &BrakedownParams<F, EF, C>, points: &[EF]) -> Vec<EF> {
        let len = pp.num_vars() - pp.num_rows().ilog2() as usize;
        lagrange_basis(&points[len..])
    }

    /// Check the merkle paths and consistency
    fn check_query_answers(
        pp: &BrakedownParams<F, EF, C>,
        challenge: &[EF],
        queries: &[usize],
        encoded_rlc_msg: &[EF],
        merkle_paths: &[H::Output],
        columns: &[F],
        commitment: &BrakedownPolyCommitment<H>,
    ) -> bool {
        // Check input length
        assert_eq!(challenge.len(), pp.num_rows());
        assert_eq!(columns.len(), queries.len() * pp.num_rows());
        assert_eq!(merkle_paths.len(), queries.len() * (commitment.depth + 1));

        // Check merkle paths and consistency.
        let (merkle_check, consistency_check) = rayon::join(
            || Self::check_merkle(pp, queries, merkle_paths, columns, commitment),
            || Self::check_consistency(pp, queries, challenge, encoded_rlc_msg, columns),
        );

        merkle_check & consistency_check
    }

    /// Check the merkle paths and consistency
    fn check_query_answers_ext(
        pp: &BrakedownParams<F, EF, C>,
        challenge: &[EF],
        queries: &[usize],
        encoded_rlc_msg: &[EF],
        merkle_paths: &[H::Output],
        columns: &[EF],
        commitment: &BrakedownPolyCommitment<H>,
    ) -> bool {
        // Check input length
        assert_eq!(challenge.len(), pp.num_rows());
        assert_eq!(columns.len(), queries.len() * pp.num_rows());
        assert_eq!(merkle_paths.len(), queries.len() * (commitment.depth + 1));

        // Check merkle paths and consistency.
        let (merkle_check, consistency_check) = rayon::join(
            || Self::check_merkle_ext(pp, queries, merkle_paths, columns, commitment),
            || Self::check_consistency_ext(pp, queries, challenge, encoded_rlc_msg, columns),
        );

        merkle_check & consistency_check
    }

    /// Check the hash of column is the same as the merkle leave.
    /// Check the merkle paths are consistent with the merkle root.
    fn check_merkle(
        pp: &BrakedownParams<F, EF, C>,
        queries: &[usize],
        merkle_paths: &[H::Output],
        columns: &[F],
        commitment: &BrakedownPolyCommitment<H>,
    ) -> bool {
        let mut check = true;

        let res: Vec<bool> = columns
            .par_chunks_exact(pp.num_rows())
            .zip(merkle_paths.par_chunks_exact(commitment.depth + 1))
            .zip(queries)
            .map(|((column, hashes), column_idx)| {
                let mut hasher = H::new();
                // Check the hash of column is the same as the merkle leave.
                column.iter().for_each(|item| unsafe {
                    #[allow(clippy::transmute_num_to_bytes)]
                    let bytes = transmute::<u64, [u8; 8]>(item.value().into());
                    hasher.update_hash_value(&bytes)
                });
                let leaf = hasher.output_reset();

                // Check the merkle path is consistent with the merkle root
                (leaf == hashes[0]) & MerkleTree::<H>::check(&commitment.root, *column_idx, hashes)
            })
            .collect();

        res.iter().for_each(|b| check &= *b);
        check
    }

    /// Check the hash of column is the same as the merkle leave.
    /// Check the merkle paths are consistent with the merkle root.
    fn check_merkle_ext(
        pp: &BrakedownParams<F, EF, C>,
        queries: &[usize],
        merkle_paths: &[H::Output],
        columns: &[EF],
        commitment: &BrakedownPolyCommitment<H>,
    ) -> bool {
        let mut check = true;

        let res: Vec<bool> = columns
            .par_chunks_exact(pp.num_rows())
            .zip(merkle_paths.par_chunks_exact(commitment.depth + 1))
            .zip(queries)
            .map(|((column, hashes), column_idx)| {
                let mut hasher = H::new();
                // Check the hash of column is the same as the merkle leave.
                column.iter().for_each(|item| unsafe {
                    item.as_base_slice().iter().for_each(|x| {
                        #[allow(clippy::transmute_num_to_bytes)]
                        let bytes = transmute::<u64, [u8; 8]>(x.value().into());
                        hasher.update_hash_value(&bytes)
                    });
                });
                let leaf = hasher.output_reset();

                // Check the merkle path is consistent with the merkle root
                (leaf == hashes[0]) & MerkleTree::<H>::check(&commitment.root, *column_idx, hashes)
            })
            .collect();

        res.iter().for_each(|b| check &= *b);
        check
    }

    /// Check the consistency of entries
    fn check_consistency(
        pp: &BrakedownParams<F, EF, C>,
        queries: &[usize],
        challenge: &[EF],
        encoded_rlc_msg: &[EF],
        columns: &[F],
    ) -> bool {
        let mut check = true;
        columns
            .chunks_exact(pp.num_rows())
            .zip(queries)
            .for_each(|(column, idx)| {
                let product = column
                    .iter()
                    .zip(challenge)
                    .fold(EF::zero(), |acc, (x0, x1)| acc + (*x1) * (*x0));

                check &= product == encoded_rlc_msg[*idx];
            });

        check
    }

    /// Check the consistency of entries
    fn check_consistency_ext(
        pp: &BrakedownParams<F, EF, C>,
        queries: &[usize],
        challenge: &[EF],
        encoded_rlc_msg: &[EF],
        columns: &[EF],
    ) -> bool {
        let mut check = true;
        columns
            .chunks_exact(pp.num_rows())
            .zip(queries)
            .for_each(|(column, idx)| {
                let product = column
                    .iter()
                    .zip(challenge)
                    .fold(EF::zero(), |acc, (x0, x1)| acc + (*x1) * (*x0));

                check &= product == encoded_rlc_msg[*idx];
            });

        check
    }

    /// Compute the residual product (i.e., the inner product)
    #[inline]
    fn residual_product(answer: &[EF], residual: &[EF]) -> EF {
        answer
            .iter()
            .zip(residual)
            .fold(EF::zero(), |acc, (x0, x1)| acc + *x0 * x1)
    }
}

impl<F, H, C, S, EF> BrakedownPCS<F, H, C, S, EF>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
    C: LinearCode<F>,
    S: LinearCodeSpec<F, Code = C>,
    EF: AbstractExtensionField<F>,
{
    /// Generate random queries.
    fn random_queries(pp: &BrakedownParams<F, EF, C>, trans: &mut Transcript<EF>) -> Vec<usize> {
        let num_queries = pp.num_query();
        let codeword_len = pp.code().codeword_len();

        let mut seed = [0u8; 16];
        trans.get_challenge_bytes(b"Generate random queries", &mut seed);
        let mut prg = Prg::from_seed(Block::from(seed));

        // Generate a random set of queries.
        if num_queries < codeword_len {
            rand::seq::index::sample(&mut prg, codeword_len, num_queries).into_vec()
        } else {
            (0..codeword_len).collect()
        }
    }
}

impl<F, H, C, S, EF> PolynomialCommitmentScheme<F, EF, S> for BrakedownPCS<F, H, C, S, EF>
where
    F: Field + Serialize + for<'de> Deserialize<'de>,
    H: Hash + Sync + Send,
    C: LinearCode<F> + Serialize + for<'de> Deserialize<'de>,
    S: LinearCodeSpec<F, Code = C>,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
{
    type Parameters = BrakedownParams<F, EF, C>;
    type Polynomial = DenseMultilinearExtension<F>;
    type EFPolynomial = DenseMultilinearExtension<EF>;
    type Commitment = BrakedownPolyCommitment<H>;
    type CommitmentState = BrakedownCommitmentState<F, H>;
    type CommitmentStateEF = BrakedownCommitmentState<EF, H>;
    type ProofEF = BrakedownOpenProofGeneral<EF, H>;
    type Proof = BrakedownOpenProof<F, H, EF>;
    type Point = EF;

    fn setup(num_vars: usize, code_spec: Option<S>) -> Self::Parameters {
        let code_spec = code_spec.expect("Need a code spec");
        BrakedownParams::<F, EF, C>::new(num_vars, code_spec)
    }

    fn commit(
        pp: &Self::Parameters,
        poly: &Self::Polynomial,
    ) -> (Self::Commitment, Self::CommitmentState) {
        // Check consistency of num_vars.
        assert!(poly.num_vars == pp.num_vars());

        // Prepare the matrix to commit.
        let num_cols = pp.code().message_len();
        let num_rows = pp.num_rows();
        let codeword_len = pp.code().codeword_len();
        let mut matrix = vec![F::zero(); num_rows * codeword_len];
        // Fill each row of the matrix with a message and
        // encode the message into a codeword.
        matrix
            .par_chunks_exact_mut(codeword_len)
            .zip(poly.evaluations.par_chunks_exact(num_cols))
            .for_each(|(row, eval)| {
                row[..num_cols].copy_from_slice(eval);
                pp.code().encode(row)
            });
        // Hash each column of the matrix into a hash value.
        // Prepare the container of the entire merkle tree, pushing the
        // layers of merkle tree into this container from bottom to top.
        let mut hashes = vec![H::Output::default(); codeword_len];

        hashes.par_iter_mut().enumerate().for_each(|(index, hash)| {
            let mut hasher = H::new();
            matrix
                .iter()
                .skip(index)
                .step_by(codeword_len)
                .for_each(|item| unsafe {
                    #[allow(clippy::transmute_num_to_bytes)]
                    let bytes = transmute::<u64, [u8; 8]>(item.value().into());
                    hasher.update_hash_value(&bytes)
                });
            *hash = hasher.output_reset();
        });

        let mut merkle_tree = MerkleTree::new();
        merkle_tree.generate(&hashes);
        let depth = merkle_tree.depth;
        let root = merkle_tree.root;

        let state = BrakedownCommitmentState {
            matrix,
            merkle_tree,
        };

        let com = BrakedownPolyCommitment { depth, root };

        (com, state)
    }

    fn commit_ef(
        pp: &Self::Parameters,
        poly: &Self::EFPolynomial,
    ) -> (Self::Commitment, Self::CommitmentStateEF) {
        // Check consistency of num_vars.
        assert!(poly.num_vars == pp.num_vars());

        // Prepare the matrix to commit.
        let num_cols = pp.code().message_len();
        let num_rows = pp.num_rows();
        let codeword_len = pp.code().codeword_len();

        let mut matrix = vec![EF::zero(); num_rows * codeword_len];

        // Fill each row of the matrix with a message and
        // encode the message into a codeword.
        matrix
            .par_chunks_exact_mut(codeword_len)
            .zip(poly.evaluations.par_chunks_exact(num_cols))
            .for_each(|(row, eval)| {
                row[..num_cols].copy_from_slice(eval);
                pp.code().encode_ext(row)
            });
        // Hash each column of the matrix into a hash value.
        // Prepare the container of the entire merkle tree, pushing the
        // layers of merkle tree into this container from bottom to top.
        let mut hashes = vec![H::Output::default(); codeword_len];

        hashes.par_iter_mut().enumerate().for_each(|(index, hash)| {
            let mut hasher = H::new();
            matrix
                .iter()
                .skip(index)
                .step_by(codeword_len)
                .for_each(|item| unsafe {
                    item.as_base_slice().iter().for_each(|x| {
                        #[allow(clippy::transmute_num_to_bytes)]
                        let bytes = transmute::<u64, [u8; 8]>(x.value().into());
                        hasher.update_hash_value(&bytes)
                    });
                });
            *hash = hasher.output_reset();
        });

        let mut merkle_tree = MerkleTree::new();
        merkle_tree.generate(&hashes);
        let depth = merkle_tree.depth;
        let root = merkle_tree.root;

        let state = BrakedownCommitmentState {
            matrix,
            merkle_tree,
        };

        let com = BrakedownPolyCommitment { depth, root };

        (com, state)
    }

    fn open(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        state: &Self::CommitmentState,
        points: &[Self::Point],
        trans: &mut Transcript<EF>,
    ) -> Self::Proof {
        assert_eq!(points.len(), pp.num_vars());
        // Hash the commitment to transcript.
        trans.append_message(b"commitment", &commitment);
        // trans.append_message(&commitment.to_bytes().unwrap());

        // Compute the tensor from the random point, see [DP23](https://eprint.iacr.org/2023/630.pdf).
        let tensor = Self::tensor_from_points(pp, points);

        let rlc_msgs = Self::answer_challenge(pp, &tensor, state);

        // Hash rlc to transcript.
        trans.append_message(b"rlc", &rlc_msgs);

        // Sample random queries.
        let queries = Self::random_queries(pp, trans);

        // Generate the proofs for random queries.
        let (merkle_paths, opening_columns) = Self::answer_queries(pp, &queries, state);

        BrakedownOpenProof {
            rlc_msgs,
            merkle_paths,
            opening_columns,
        }
    }

    fn open_ef(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        state: &Self::CommitmentStateEF,
        points: &[Self::Point],
        trans: &mut Transcript<EF>,
    ) -> Self::ProofEF {
        assert_eq!(points.len(), pp.num_vars());
        // Hash the commitment to transcript.
        trans.append_message(b"commitment", &commitment);
        // trans.append_message(&commitment.to_bytes().unwrap());

        // Compute the tensor from the random point, see [DP23](https://eprint.iacr.org/2023/630.pdf).
        let tensor = Self::tensor_from_points(pp, points);

        let rlc_msgs = Self::answer_challenge_ext(pp, &tensor, state);

        // Hash rlc to transcript.
        trans.append_message(b"rlc", &rlc_msgs);

        // Sample random queries.
        let queries = Self::random_queries(pp, trans);

        // Generate the proofs for random queries.
        let (merkle_paths, opening_columns) = Self::answer_queries_ext(pp, &queries, state);

        BrakedownOpenProofGeneral {
            rlc_msgs,
            merkle_paths,
            opening_columns,
        }
    }
    fn batch_open(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        state: &Self::CommitmentState,
        batch_points: &[Vec<Self::Point>],
        trans: &mut Transcript<EF>,
    ) -> Vec<Self::Proof> {
        // Hash the commitment to transcript.
        trans.append_message(b"commitment", &commitment);

        // Compute the tensor from the random point, see [DP23](https://eprint.iacr.org/2023/630.pdf).
        let tensors: Vec<Vec<EF>> = batch_points
            .iter()
            .map(|points| {
                assert_eq!(points.len(), pp.num_vars());
                Self::tensor_from_points(pp, points)
            })
            .collect();

        let rlc_msgss: Vec<Vec<EF>> = tensors
            .par_iter()
            .map(|tensor| Self::answer_challenge(pp, tensor, state))
            .collect();

        let queries_vec: Vec<Vec<usize>> = rlc_msgss
            .iter()
            .map(|rlc_msg| {
                trans.append_message(b"rlc", rlc_msg);
                Self::random_queries(pp, trans)
            })
            .collect();

        queries_vec
            .par_iter()
            .zip(rlc_msgss.par_iter())
            .map(|(queries, rlc_msgs)| {
                let (merkle_paths, opening_columns) = Self::answer_queries(pp, queries, state);
                BrakedownOpenProof {
                    rlc_msgs: rlc_msgs.clone(),
                    merkle_paths,
                    opening_columns,
                }
            })
            .collect()
    }

    fn batch_open_ef(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        state: &Self::CommitmentStateEF,
        batch_points: &[Vec<Self::Point>],
        trans: &mut Transcript<EF>,
    ) -> Vec<Self::ProofEF> {
        // Hash the commitment to transcript.
        trans.append_message(b"commitment", &commitment);

        // Compute the tensor from the random point, see [DP23](https://eprint.iacr.org/2023/630.pdf).
        let tensors: Vec<Vec<EF>> = batch_points
            .iter()
            .map(|points| {
                assert_eq!(points.len(), pp.num_vars());
                Self::tensor_from_points(pp, points)
            })
            .collect();

        let rlc_msgss: Vec<Vec<EF>> = tensors
            .par_iter()
            .map(|tensor| Self::answer_challenge_ext(pp, tensor, state))
            .collect();

        let queries_vec: Vec<Vec<usize>> = rlc_msgss
            .iter()
            .map(|rlc_msg| {
                trans.append_message(b"rlc", rlc_msg);
                Self::random_queries(pp, trans)
            })
            .collect();

        queries_vec
            .par_iter()
            .zip(rlc_msgss.par_iter())
            .map(|(queries, rlc_msgs)| {
                let (merkle_paths, opening_columns) = Self::answer_queries_ext(pp, queries, state);
                BrakedownOpenProofGeneral {
                    rlc_msgs: rlc_msgs.clone(),
                    merkle_paths,
                    opening_columns,
                }
            })
            .collect()
    }

    fn verify(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        points: &[Self::Point],
        eval: Self::Point,
        proof: &Self::Proof,
        trans: &mut Transcript<EF>,
    ) -> bool {
        assert_eq!(points.len(), pp.num_vars());

        // Hash the commitment to transcript.
        trans.append_message(b"commitment", &commitment);

        let (tensor, residual) = Self::tensor_decompose(pp, points);

        // Encode the answered random linear combination.
        assert_eq!(proof.rlc_msgs.len(), pp.code().message_len());
        let mut encoded_msg = vec![EF::zero(); pp.code().codeword_len()];
        encoded_msg[..proof.rlc_msgs.len()].copy_from_slice(&proof.rlc_msgs);
        pp.code().encode_ext(&mut encoded_msg);

        // Hash rlc to transcript.
        trans.append_message(b"rlc", &proof.rlc_msgs);

        // Sample random queries.
        let queries = Self::random_queries(pp, trans);

        // Proximity check.
        let mut check = Self::check_query_answers(
            pp,
            &tensor,
            &queries,
            &encoded_msg,
            &proof.merkle_paths,
            &proof.opening_columns,
            commitment,
        );

        // Consistency check.
        check &= eval == Self::residual_product(&proof.rlc_msgs, &residual);

        check
    }

    fn verify_ef(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        points: &[Self::Point],
        eval: Self::Point,
        proof: &Self::ProofEF,
        trans: &mut Transcript<EF>,
    ) -> bool {
        assert_eq!(points.len(), pp.num_vars());

        // Hash the commitment to transcript.
        trans.append_message(b"commitment", &commitment);

        let (tensor, residual) = Self::tensor_decompose(pp, points);

        // Encode the answered random linear combination.
        assert_eq!(proof.rlc_msgs.len(), pp.code().message_len());
        let mut encoded_msg = vec![EF::zero(); pp.code().codeword_len()];
        encoded_msg[..proof.rlc_msgs.len()].copy_from_slice(&proof.rlc_msgs);
        pp.code().encode_ext(&mut encoded_msg);

        // Hash rlc to transcript.
        trans.append_message(b"rlc", &proof.rlc_msgs);

        // Sample random queries.
        let queries = Self::random_queries(pp, trans);

        // Proximity check.
        let mut check = Self::check_query_answers_ext(
            pp,
            &tensor,
            &queries,
            &encoded_msg,
            &proof.merkle_paths,
            &proof.opening_columns,
            commitment,
        );

        // Consistency check.
        check &= eval == Self::residual_product(&proof.rlc_msgs, &residual);

        check
    }

    fn batch_verify(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        batch_points: &[Vec<Self::Point>],
        evals: &[Self::Point],
        proofs: &[Self::Proof],
        trans: &mut Transcript<EF>,
    ) -> bool {
        // Hash the commitment to transcript.
        trans.append_message(b"commitment", &commitment);

        let tensors_and_residuals: Vec<(Vec<EF>, Vec<EF>)> = batch_points
            .par_iter()
            .map(|points| {
                assert_eq!(points.len(), pp.num_vars());
                Self::tensor_decompose(pp, points)
            })
            .collect();

        let queries_vec: Vec<Vec<usize>> = proofs
            .iter()
            .map(|proof| {
                assert_eq!(proof.rlc_msgs.len(), pp.code().message_len());
                trans.append_message(b"rlc", &proof.rlc_msgs);
                Self::random_queries(pp, trans)
            })
            .collect();

        izip!(proofs, &queries_vec, &tensors_and_residuals, evals)
            .par_bridge()
            .all(|(proof, queries, (tensor, residual), eval)| {
                assert_eq!(proof.rlc_msgs.len(), pp.code().message_len());
                let mut encoded_msg = vec![EF::zero(); pp.code().codeword_len()];
                encoded_msg[..proof.rlc_msgs.len()].copy_from_slice(&proof.rlc_msgs);
                pp.code().encode_ext(&mut encoded_msg);

                Self::check_query_answers(
                    pp,
                    tensor,
                    queries,
                    &encoded_msg,
                    &proof.merkle_paths,
                    &proof.opening_columns,
                    commitment,
                ) & (*eval == Self::residual_product(&proof.rlc_msgs, residual))
            })
    }

    fn batch_verify_ef(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        batch_points: &[Vec<Self::Point>],
        evals: &[Self::Point],
        proofs: &[Self::ProofEF],
        trans: &mut Transcript<EF>,
    ) -> bool {
        // Hash the commitment to transcript.
        trans.append_message(b"commitment", &commitment);

        let tensors_and_residuals: Vec<(Vec<EF>, Vec<EF>)> = batch_points
            .par_iter()
            .map(|points| {
                assert_eq!(points.len(), pp.num_vars());
                Self::tensor_decompose(pp, points)
            })
            .collect();

        let queries_vec: Vec<Vec<usize>> = proofs
            .iter()
            .map(|proof| {
                assert_eq!(proof.rlc_msgs.len(), pp.code().message_len());
                trans.append_message(b"rlc", &proof.rlc_msgs);
                Self::random_queries(pp, trans)
            })
            .collect();

        izip!(proofs, &queries_vec, &tensors_and_residuals, evals)
            .par_bridge()
            .all(|(proof, queries, (tensor, residual), eval)| {
                assert_eq!(proof.rlc_msgs.len(), pp.code().message_len());
                let mut encoded_msg = vec![EF::zero(); pp.code().codeword_len()];
                encoded_msg[..proof.rlc_msgs.len()].copy_from_slice(&proof.rlc_msgs);
                pp.code().encode_ext(&mut encoded_msg);

                Self::check_query_answers_ext(
                    pp,
                    tensor,
                    queries,
                    &encoded_msg,
                    &proof.merkle_paths,
                    &proof.opening_columns,
                    commitment,
                ) & (*eval == Self::residual_product(&proof.rlc_msgs, residual))
            })
    }
}
