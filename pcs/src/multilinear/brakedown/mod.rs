mod data_structure;
/// prover of brakedown pcs
pub mod prover;
/// verifier of brakedown pcs
pub mod verifier;

use std::marker::PhantomData;

use algebra::{
    utils::{Block, Prg, Transcript},
    DenseMultilinearExtension, Field,
};
pub use data_structure::{
    BrakedownCommitmentState, BrakedownOpenProof, BrakedownParams, BrakedownPolyCommitment,
};
use itertools::Itertools;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

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
pub struct BrakedownPCS<F, H, C, S>(PhantomData<(F, H, C, S)>)
where
    F: Field,
    H: Hash,
    C: LinearCode<F>,
    S: LinearCodeSpec<F, Code = C>;

impl<F, H, C, S> BrakedownPCS<F, H, C, S>
where
    F: Field,
    H: Hash,
    C: LinearCode<F>,
    S: LinearCodeSpec<F, Code = C>,
{
    /// Prover answers the challenge by computing the product of the challenge vector
    /// and the commited matirx.
    /// The computation of the product can be viewed as a linear combination of rows
    /// of the matrix with challenge vector as the coefficients.
    fn answer_challenge(
        pp: &BrakedownParams<F, C>,
        challenge: &[F],
        state: &BrakedownCommitmentState<F, H>,
    ) -> Vec<F> {
        assert_eq!(challenge.len(), pp.num_rows());
        let num_cols = pp.code().message_len();
        let codeword_len = pp.code().codeword_len();

        // Compute the answer as a linear combination.
        let mut answer = vec![F::ZERO; num_cols];
        state
            .matrix
            .chunks_exact(codeword_len)
            .zip(challenge)
            .for_each(|(row, coeff)| {
                row.iter()
                    .take(num_cols)
                    .enumerate()
                    .for_each(|(idx, item)| {
                        answer[idx] += (*item) * coeff;
                    })
            });
        answer
    }

    /// Prover answers the query of columns of given indices
    /// and gives merkle paths as the proof of its consistency with the merkle root.
    fn answer_queries(
        pp: &BrakedownParams<F, C>,
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

    /// Decompose an evaluation of point x into two tensors q1, q2 such that
    /// f(x) = q1 * M * q2 where M is the committed matrix.
    fn tensor_decompose(pp: &BrakedownParams<F, C>, point: &[F]) -> (Vec<F>, Vec<F>) {
        let left_point_len = pp.num_rows().ilog2() as usize;
        let right_point_len = pp.code().message_len().ilog2() as usize;
        assert_eq!(left_point_len + right_point_len, point.len());

        let challenge = lagrange_basis(&point[right_point_len..]);

        let residual_tensor = lagrange_basis(&point[..right_point_len]);

        assert_eq!(challenge.len(), pp.num_rows());
        assert_eq!(residual_tensor.len(), pp.code().message_len());

        (challenge, residual_tensor)
    }

    /// Check the merkle paths and consistency
    fn check_query_answers(
        pp: &BrakedownParams<F, C>,
        challenge: &[F],
        queries: &[usize],
        rlc_msg: &[F],
        merkle_paths: &[H::Output],
        columns: &[F],
        commitment: &BrakedownPolyCommitment<H>,
    ) -> bool {
        // Check input length
        assert_eq!(challenge.len(), pp.num_rows());
        assert_eq!(columns.len(), queries.len() * pp.num_rows());
        assert_eq!(merkle_paths.len(), queries.len() * (commitment.depth + 1));

        // Check merkle paths.
        let merkle_check = Self::check_merkle(pp, queries, merkle_paths, columns, commitment);
        println!("merkle check: {:?}", merkle_check);

        // Check consistency.
        let consistency_check = Self::check_consistency(pp, queries, challenge, rlc_msg, columns);
        println!("consistency check: {:?}", consistency_check);

        merkle_check & consistency_check
    }

    /// Check the hash of column is the same as the merkle leave.
    /// Check the merkle paths are consistent with the merkle root.
    fn check_merkle(
        pp: &BrakedownParams<F, C>,
        queries: &[usize],
        merkle_paths: &[H::Output],
        columns: &[F],
        commitment: &BrakedownPolyCommitment<H>,
    ) -> bool {
        let mut check = true;
        let mut hasher = H::new();

        columns
            .chunks_exact(pp.num_rows())
            .zip(merkle_paths.chunks_exact(commitment.depth + 1))
            .zip(queries)
            .for_each(|((column, hashes), column_idx)| {
                // Check the hash of column is the same as the merkle leave.
                column
                    .iter()
                    .for_each(|item| hasher.update_string(item.to_string()));
                let leaf = hasher.output_reset();

                // Check the merkle path is consistent with the merkle root
                check &= (leaf == hashes[0])
                    & MerkleTree::<H>::check(&commitment.root, *column_idx, hashes);
            });
        check
    }

    /// Check the consistency of entries
    fn check_consistency(
        pp: &BrakedownParams<F, C>,
        queries: &[usize],
        challenge: &[F],
        rlc_msg: &[F],
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
                    .fold(F::ZERO, |acc, (x0, x1)| acc + *x0 * x1);

                check &= product == rlc_msg[*idx];
            });

        check
    }

    /// Compute the residual product (i.e., the inner product)
    #[inline]
    fn residual_product(answer: &[F], residual: &[F]) -> F {
        answer
            .iter()
            .zip(residual)
            .fold(F::ZERO, |acc, (x0, x1)| acc + *x0 * x1)
    }
}

impl<F, H, C, S> BrakedownPCS<F, H, C, S>
where
    F: Field + Serialize,
    H: Hash,
    C: LinearCode<F>,
    S: LinearCodeSpec<F, Code = C>,
{
    /// Generate random queries.
    fn random_queries(pp: &BrakedownParams<F, C>, trans: &mut Transcript<F>) -> Vec<usize> {
        let num_queries = pp.num_query();
        let codeword_len = pp.code().codeword_len();

        let mut seed = [0u8; 16];
        trans.get_challenge_bytes(&mut seed);
        let mut prg = Prg::from_seed(Block::from(seed));

        // Generate a random set of queries.
        if num_queries < codeword_len {
            rand::seq::index::sample(&mut prg, codeword_len, num_queries).into_vec()
        } else {
            (0..codeword_len).collect()
        }
    }
}

impl<F, H, C, S> PolynomialCommitmentScheme<F, S> for BrakedownPCS<F, H, C, S>
where
    F: Field + Serialize,
    H: Hash,
    C: LinearCode<F> + Serialize + for<'de> Deserialize<'de>,
    S: LinearCodeSpec<F, Code = C>,
{
    type Parameters = BrakedownParams<F, C>;
    type Polynomial = DenseMultilinearExtension<F>;
    type Commitment = BrakedownPolyCommitment<H>;
    type CommitmentState = BrakedownCommitmentState<F, H>;
    type Proof = BrakedownOpenProof<F, H>;

    fn setup(
        num_vars: usize,
        code_spec: Option<S>,
        rng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> Self::Parameters {
        let code_spec = code_spec.expect("Need a code spec");
        BrakedownParams::<F, C>::new(num_vars, code_spec, rng)
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

        let mut matrix = vec![F::ZERO; num_rows * codeword_len];

        // Fill each row of the matrix with a message and
        // encode the message into a codeword.
        matrix
            .chunks_exact_mut(codeword_len)
            .zip(poly.evaluations.chunks_exact(num_cols))
            .for_each(|(row, eval)| {
                row[..num_cols].copy_from_slice(eval);
                pp.code().encode(row)
            });

        // Hash each column of the matrix into a hash value.
        // Prepare the container of the entire merkle tree, pushing the
        // layers of merkle tree into this container from bottom to top.
        let mut hashes = vec![H::Output::default(); codeword_len];
        let mut hasher = H::new();
        hashes.iter_mut().enumerate().for_each(|(index, hash)| {
            matrix
                .iter()
                .skip(index)
                .step_by(codeword_len)
                .for_each(|item| hasher.update_string(item.to_string()));
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
        point: &crate::Point<F, Self::Polynomial>,
        trans: &mut Transcript<F>,
    ) -> Self::Proof {
        // Hash the parameters and the commitment to transcript.
        trans.append_message(&pp.to_bytes().unwrap());
        trans.append_message(&commitment.to_bytes().unwrap());

        // Apply FS to get the random challenge.
        let challenge = trans.get_vec_and_append_challenge(pp.num_rows());

        // Generate the random linear combination of the rows of the message.
        let rlc_msgs = Self::answer_challenge(pp, &challenge, state);

        // Hash rlc to transcript.
        trans.append_elements(&rlc_msgs);

        // Sample random queries.
        let queries = Self::random_queries(pp, trans);

        // Generate the proofs for random queries.
        let (merkle_paths, opening_columns) = Self::answer_queries(pp, &queries, state);

        let (tensor, _) = Self::tensor_decompose(pp, point);
        println!("prover tensor: {:?}", tensor);

        let partial_product = Self::answer_challenge(pp, &tensor, state);

        BrakedownOpenProof {
            rlc_msgs,
            opening_columns,
            merkle_paths,
            partial_product,
        }
    }

    fn verify(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        point: &crate::Point<F, Self::Polynomial>,
        eval: F,
        proof: &Self::Proof,
        trans: &mut Transcript<F>,
    ) -> bool {
        // Hash the parameters and the commitment to transcript.
        trans.append_message(&pp.to_bytes().unwrap());
        trans.append_message(&commitment.to_bytes().unwrap());

        // Apply FS to get the random challenge.
        let challenge = trans.get_vec_and_append_challenge(pp.num_rows());

        // Encode the answered random linear combination.
        assert_eq!(proof.rlc_msgs.len(), pp.code().message_len());
        let mut encoded_msg = vec![F::ZERO; pp.code().codeword_len()];
        encoded_msg[..proof.rlc_msgs.len()].copy_from_slice(&proof.rlc_msgs);
        pp.code().encode(&mut encoded_msg);

        // Hash rlc to transcript.
        trans.append_elements(&proof.rlc_msgs);

        // Sample random queries.
        let queries = Self::random_queries(pp, trans);

        let mut check = Self::check_query_answers(
            pp,
            &challenge,
            &queries,
            &encoded_msg,
            &proof.merkle_paths,
            &proof.opening_columns,
            commitment,
        );

        println!("proximity check: {:?}", check);

        let (tensor, residual) = Self::tensor_decompose(pp, point);

        println!("verifier tensor: {:?}", tensor);

        // Encode partial_product
        assert_eq!(proof.partial_product.len(), pp.code().message_len());
        encoded_msg[..proof.partial_product.len()].copy_from_slice(&proof.partial_product);
        pp.code().encode(&mut encoded_msg);

        check &= Self::check_query_answers(
            pp,
            &tensor,
            &queries,
            &encoded_msg,
            &proof.merkle_paths,
            &proof.opening_columns,
            commitment,
        );

        println!("tensor check: {:?}", check);

        check &= eval == Self::residual_product(&proof.partial_product, &residual);

        check
    }
}
