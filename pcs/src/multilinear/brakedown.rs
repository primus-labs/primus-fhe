use crate::{
    //multilinear::PolynomialCommitmentScheme,
    utils::code::{BrakedownCode, BrakedownCodeSpec, LinearCode},
};

use algebra::{DenseMultilinearExtension, Field, FieldUniformSampler};

use rand::{distributions::Uniform, Rng, RngCore};
use sha3::{Digest, Sha3_256};
use std::marker::PhantomData;

///
// #[derive(Clone, Debug, Default)]
// struct MultilinearBrakedownCommitment<F, H> {
//     rows: Vec<F>,
//     merkle_tree: Vec<H>,
//     root: H,
// }

///(PhantomData<(F, Hash, BrakedownCodeSpec)>);
// #[derive(Debug, Clone)]
// pub struct MultilinearBrakedown<F: Field>(PhantomData<(F, Hash, BrakedownCodeSpec)>);
// impl<F: Field> PolynomialCommitmentScheme<F, BrakedownCodeSpec> for MultilinearBrakedown<F> {
//     type ProverParam = MultilinearBrakedownParam<F>;
//     type VerifierParam = MultilinearBrakedownParam<F>;
//     type Polynomial = DenseMultilinearExtension<F>;
//     type Commitment = MultilinearBrakedownCommitment<F, Hash>;
//     type CommitmentChunk = Hash;

//     fn setup(
//         poly_size: usize,
//         spec: BrakedownCodeSpec,
//         rng: impl RngCore,
//     ) -> (Self::ProverParam, Self::VerifierParam) {
//         assert!(poly_size.is_power_of_two());
//         let num_vars = poly_size.ilog2() as usize;
//         let message_len = 10; /////// to do
//         let brakedown: BrakedownCode<F> = BrakedownCode::new(spec, message_len, rng);
//         let param = MultilinearBrakedownParam {
//             num_vars,
//             num_rows: (1 << num_vars) / brakedown.message_len(),
//             brakedown,
//         };
//         let pp = param.clone();
//         let vp = param;
//         (pp, vp)
//     }

//     fn commit(pp: &Self::ProverParam, poly: &Self::Polynomial) -> Self::Commitment {
//         // input check

//         // prepare vectors to commit

//         let message_len = pp.brakedown.message_len();
//         let codeword_len = pp.brakedown.codeword_len();
//         let mut rows = vec![F::ZERO; pp.num_rows * codeword_len];

//         // encode rows
//         rows.chunks_exact_mut(codeword_len)
//             .zip(poly.evaluations.chunks_exact(codeword_len))
//             .for_each(|(row, eval)| {
//                 row[..eval.len()].copy_from_slice(eval);
//                 pp.brakedown.encode(row)
//             });

//         // hash columns
//         let depth = codeword_len.next_power_of_two().ilog2() as usize;
//         let mut hashes: Vec<Hash> = vec![Hash::default(); (1 << (depth + 1)) - 1];
//         hashes[..codeword_len]
//             .iter_mut()
//             .enumerate()
//             .for_each(|(index, hash)| {
//                 let mut hasher = Sha3_256::new();
//                 rows.iter()
//                     .skip(index)
//                     .step_by(codeword_len)
//                     .for_each(|item| hasher.update(item.to_string()));
//                 hash.copy_from_slice(hasher.finalize().as_slice());
//             });

//         // merklize column hashes
//         let mut offset = 0;

//         for depth in (1..=depth).rev() {
//             let input_len = 1 << depth;
//             let output_len = input_len >> 1;

//             let (input, output) =
//                 hashes[offset..offset + input_len + output_len].split_at_mut(offset + input_len);

//             let mut hasher = Sha3_256::new();
//             input
//                 .chunks_exact(2)
//                 .zip(output.iter_mut())
//                 .for_each(|(input_pair, output_item)| {
//                     hasher.update(&input_pair[0]);
//                     hasher.update(&input_pair[1]);
//                     output_item.copy_from_slice(hasher.finalize_reset().as_slice());
//                 });

//             offset += input_len;
//         }

//         MultilinearBrakedownCommitment {
//             rows,
//             root: hashes.last().unwrap().clone(),
//             merkle_tree: hashes,
//         }
//     }

//     fn open(
//         pp: &Self::ProverParam,
//         poly: &Self::Polynomial,
//         comm: &Self::Commitment,
//         point: &super::Point<F, Self::Polynomial>,
//         eval: &F,
//     ) {
//     }

//     fn verify(
//         vp: &Self::VerifierParam,
//         comm: &Self::Commitment,
//         point: &super::Point<F, Self::Polynomial>,
//         eval: &F,
//     ) {
//     }
// }

/// Parameters
#[derive(Clone, Debug, Default)]
pub struct BrakedownParam<F: Field> {
    ///
    pub num_vars: usize,
    num_rows: usize,
    ///
    pub brakedown: BrakedownCode<F>,
}

type ProverParam<F> = BrakedownParam<F>;
type VerifierParam<F> = BrakedownParam<F>;
type Polynomial<F> = DenseMultilinearExtension<F>;
// type Point<F> = <DenseMultilinearExtension<F> as MultilinearExtension<F>>::Point;

/// we use 256bit long hash value
type Hash = [u8; 32];

/// Protocol of Brakedown PCS
#[derive(Debug, Clone)]
pub struct BrakedownProtocol<F: Field> {
    field: PhantomData<F>,
}

impl<F: Field> BrakedownProtocol<F> {
    ///
    pub fn setup(
        num_vars: usize,
        message_len: usize,
        spec: BrakedownCodeSpec,
        rng: impl RngCore,
    ) -> (ProverParam<F>, VerifierParam<F>) {
        // input check
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
    pp: ProverParam<F>,
    ///
    pub rows: Vec<F>,
    merkle_tree: Vec<Hash>,
    root: Hash,
}

impl<F: Field> BrakedownProver<F> {
    ///
    #[inline]
    pub fn new(pp: ProverParam<F>) -> Self {
        BrakedownProver {
            pp,
            rows: Vec::new(),
            merkle_tree: Vec::new(),
            root: Hash::default(),
        }
    }

    ///
    #[inline]
    pub fn commit_poly(&mut self, poly: &Polynomial<F>) -> Hash {
        // input check

        // prepare vectors to commit
        let pp = &self.pp;
        let message_len = pp.brakedown.message_len();
        let codeword_len = pp.brakedown.codeword_len();
        let mut rows = vec![F::ZERO; pp.num_rows * codeword_len];

        // encode rows
        rows.chunks_exact_mut(codeword_len)
            .zip(poly.evaluations.chunks_exact(message_len))
            .for_each(|(row, eval)| {
                row[..eval.len()].copy_from_slice(eval);
                pp.brakedown.encode(row)
            });

        // hash columns
        let depth = codeword_len.next_power_of_two().ilog2() as usize;
        let mut hashes: Vec<Hash> = vec![Hash::default(); (1 << (depth + 1)) - 1];
        hashes[..codeword_len]
            .iter_mut()
            .enumerate()
            .for_each(|(index, hash)| {
                let mut hasher = Sha3_256::new();
                rows.iter()
                    .skip(index)
                    .step_by(codeword_len)
                    .for_each(|item| hasher.update(item.to_string()));
                hash.copy_from_slice(hasher.finalize().as_slice());
            });

        // merklize column hashes
        let mut offset = 0;

        for depth in (1..=depth).rev() {
            let input_len = 1 << depth;
            let output_len = input_len >> 1;

            let (input, output) =
                hashes[offset..offset + input_len + output_len].split_at_mut(input_len);

            let mut hasher = Sha3_256::new();
            input
                .chunks_exact(2)
                .zip(output.iter_mut())
                .for_each(|(input_pair, output_item)| {
                    hasher.update(input_pair[0]);
                    hasher.update(input_pair[1]);
                    output_item.copy_from_slice(hasher.finalize_reset().as_slice());
                });

            offset += input_len;
        }

        self.rows = rows;
        self.root = *hashes.last().unwrap();
        self.merkle_tree = hashes;

        self.root
    }

    ///
    #[inline]
    pub fn answer_challenge(&self, challenge: &Vec<F>) -> Vec<F> {
        let coeffs = challenge;
        let message_len = self.pp.brakedown.message_len();
        let codeword_len = self.pp.brakedown.codeword_len();
        let mut answer = vec![F::ZERO; message_len];
        self.rows
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

    ///
    #[inline]
    pub fn answer_openings(&self, openings: &[usize]) -> (Vec<Vec<Hash>>, Vec<Vec<F>>) {
        // double Vec is Ok?
        let codeword_len = self.pp.brakedown.codeword_len();
        let num_rows = self.pp.num_rows;

        (
            openings.iter().map(|idx| self.open_merkle(*idx)).collect(),
            openings
                .iter()
                .map(|idx| {
                    (0..num_rows)
                        .map(|row_idx| self.rows[row_idx * codeword_len + idx])
                        .collect()
                })
                .collect(),
        )
    }

    #[inline]
    fn open_merkle(&self, column_idx: usize) -> Vec<Hash> {
        let mut offset = 0;
        let depth = self.pp.brakedown.codeword_len().next_power_of_two().ilog2() as usize;
        let mut merkle_path: Vec<Hash> = Vec::new();
        (1..=depth).rev().enumerate().for_each(|(idx, depth)| {
            let layer_len = 1 << depth;
            let neighbour_idx = (column_idx >> idx) ^ 1;
            merkle_path.push(self.merkle_tree[offset + neighbour_idx]);
            offset += layer_len;
        });
        merkle_path
    }
}

/// Verifier of Brakedown PCS
#[derive(Debug, Clone, Default)]
pub struct BrakedownVerifier<F: Field, R: RngCore> {
    vp: VerifierParam<F>,
    randomness: R,
    root: Hash,
    challenge: Vec<F>,
    ///
    pub answer: Vec<F>,
    openings: Vec<usize>,
    right_tensor: Vec<F>,
}

impl<F: Field, R: RngCore> BrakedownVerifier<F, R> {
    ///
    #[inline]
    pub fn new(vp: VerifierParam<F>, randomness: R) -> Self {
        BrakedownVerifier {
            vp,
            randomness,
            root: Hash::default(),
            challenge: Vec::new(),
            answer: Vec::new(),
            openings: Vec::new(),
            right_tensor: Vec::new(),
        }
    }

    ///
    #[inline]
    pub fn receive_root(&mut self, root: Hash) {
        self.root = root;
    }

    ///
    #[inline]
    pub fn random_challenge(&mut self) -> &Vec<F> {
        let field_distr: FieldUniformSampler<F> = FieldUniformSampler::new();
        self.challenge = (&mut self.randomness)
            .sample_iter(field_distr)
            .take(self.vp.num_rows)
            .collect();
        &self.challenge
    }

    ///
    #[inline]
    pub fn random_openings(&mut self) -> &Vec<usize> {
        // in toy example, num_opening > codeword_len may happen
        let num_opening = self.vp.brakedown.spec.num_opening();
        let codeword_len = self.vp.brakedown.codeword_len();
        if num_opening < codeword_len {
            let index_distr: Uniform<usize> = Uniform::new(0, self.vp.brakedown.codeword_len());
            self.openings = (&mut self.randomness)
                .sample_iter(index_distr)
                .take(num_opening)
                .collect();
        } else {
            self.openings = (0..codeword_len).collect::<Vec<usize>>();
        }
        &self.openings
    }

    ///
    #[inline]
    pub fn receive_answer(&mut self, mut answer: Vec<F>) {
        assert!(answer.len() == self.vp.brakedown.message_len());
        answer.resize(self.vp.brakedown.codeword_len(), F::ZERO);
        self.vp.brakedown.encode(&mut answer);
        assert!(answer.len() == self.vp.brakedown.codeword_len());
        self.answer = answer;
    }

    ///
    #[inline]
    pub fn check_answer(&mut self, merkle_paths: Vec<Vec<Hash>>, columns: Vec<Vec<F>>) {
        assert!(self.challenge.len() == self.vp.num_rows);
        assert!(columns.len() == self.openings.len());
        assert!(merkle_paths.len() == self.openings.len());

        self.check_merkle(&merkle_paths, &columns);
        self.check_consistency(&columns);
    }

    #[inline]
    fn check_merkle(&self, merkle_paths: &Vec<Vec<Hash>>, columns: &[Vec<F>]) {
        columns
            .iter()
            .zip(merkle_paths)
            .zip(&self.openings)
            .for_each(|((column, hashes), column_idx)| {
                let mut hasher = Sha3_256::new();
                column
                    .iter()
                    .for_each(|item| hasher.update(item.to_string()));
                let mut leaf = Hash::default();
                leaf.copy_from_slice(hasher.finalize_reset().as_slice());

                let root = hashes.iter().enumerate().fold(leaf, |acc, (idx, hash)| {
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

    #[inline]
    fn check_consistency(&self, columns: &[Vec<F>]) {
        columns
            .iter()
            .zip(&self.openings)
            .for_each(|(column, idx)| {
                assert!(column.len() == self.vp.num_rows);
                let product = column
                    .iter()
                    .zip(&self.challenge)
                    .map(|(x0, x1)| *x0 * x1)
                    .fold(F::ZERO, |acc, x| acc + x);
                assert!(product == self.answer[*idx]);
            })
    }

    ///
    #[inline]
    pub fn tensor_decompose(&mut self, points: &Vec<F>) -> Vec<F> {
        let left = self.vp.num_rows.ilog2() as usize;
        let right = self.vp.brakedown.message_len().ilog2() as usize;
        assert!(left + right == points.len());
        // a n-dimensional point (x0, x1, x2, ..., xn-1) is viewed as n 1-dimensional points here

        //self.challenge = Self::lagrange_basis(&points[..left]);
        //self.right_tensor = Self::lagrange_basis(&points[left..]);
        self.challenge = Self::lagrange_basis(&points[left..]);
        self.right_tensor = Self::lagrange_basis(&points[..left]);

        assert!(self.challenge.len() == self.vp.num_rows);
        assert!(self.right_tensor.len() == self.vp.brakedown.message_len());

        self.challenge.clone()
    }

    #[inline]
    fn lagrange_basis(points: &[F]) -> Vec<F> {
        let mut basis = vec![F::ONE];
        // a n-dimensional point (x0, x1, x2, ..., xn-1) is viewed as n 1-dimensional points here
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

    ///
    pub fn residual_product(&self) -> F {
        self.answer
            .iter()
            .zip(&self.right_tensor)
            .map(|(x0, x1)| *x0 * x1)
            .fold(F::ZERO, |acc, add| acc + add)
    }
}

// #[inline]
// fn product(
//     pp: <Self as PolynomialCommitmentScheme<F, BrakedownCodeSpec>>::ProverParam,
//     poly: <Self as PolynomialCommitmentScheme<F, BrakedownCodeSpec>>::Polynomial,
//     coeffs: Vec<F>,
// ) -> Vec<F> {
//     let message_len = pp.brakedown.message_len();
//     let mut combined = vec![F::ZERO; message_len];
//     poly.evaluations
//         .chunks_exact(message_len)
//         .zip(coeffs)
//         .for_each(|(row, coeff)| {
//             row.iter().enumerate().for_each(|(idx, item)| {
//                 combined[idx] += (*item) * coeff;
//             })
//         });
//     combined
// }
