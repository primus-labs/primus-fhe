// use crate::utils::{
//     arithmetic::lagrange_basis,
//     merkle_tree::{MerkleRoot, MerkleTree},
// };

// use super::*;

// /// Verifier of Brakedown PCS
// #[derive(Debug, Clone, Default)]
// pub struct PcsVerifier<F: Field, C: LinearCode<F>, H: Hash, R: Rng + CryptoRng + Default> {
//     /// brakedown pcs parameter
//     vp: VerifierParam<F, C, H>,

//     /// verifier challenges prover using this source of randomness
//     /// which can be substituted by Fiat-Shamir transformation
//     randomness: R,

//     /// commitment of the polynomia i.e. the merkle root
//     root: MerkleRoot<H>,

//     /// chanllenge,
//     /// either a random vector or
//     /// a tensor of the point that the verifier wants to evaluate at
//     challenge: Vec<F>,

//     /// answer of the chanllenge
//     answer: Vec<F>,

//     /// indexes of queries
//     queries: Vec<usize>,

//     /// decompose a point into two tensors,
//     /// store one tensor in the challenge and
//     /// store the other one in this residual tensor
//     residual_tensor: Vec<F>,
// }

// impl<F: Field, C: LinearCode<F>, H: Hash, R: Rng + CryptoRng + Default> PcsVerifier<F, C, H, R> {
//     /// create a verifier
//     #[inline]
//     pub fn new(vp: VerifierParam<F, C, H>, randomness: R) -> Self {
//         PcsVerifier {
//             vp,
//             randomness,
//             ..Default::default()
//         }
//     }

//     /// the soundness error specified by the security parameter for proximity test: (1-delta/3)^num_opening + (codeword_len/|F|)
//     /// return the number of columns needed to open, which accounts for the (1-delta/3)^num_opening part
//     #[inline]
//     pub fn num_query(&self) -> usize {
//         let num_query = ceil(
//             -(self.vp.security_bit as f64)
//                 / (1.0 - self.vp.code.distance() * self.vp.code.proximity_gap()).log2(),
//         );
//         min(num_query, self.vp.code.codeword_len())
//     }

//     /// return the size of proof given column_num c and row_num r, which consists of the following two parts:
//     /// size of the product of random vector and commited matrix: 1*c
//     /// size of the random selected columns of commited matrix: self.spec.num_opening() * r
//     #[inline]
//     pub fn proof_size(&self, c: usize, r: usize) -> usize {
//         c + self.num_query() * r
//     }

//     /// receive the commitment i.e. the merkle root
//     #[inline]
//     pub fn receive_root(&mut self, root: &MerkleRoot<H>) {
//         self.root = root.clone();
//     }

//     /// generate a random challenge
//     #[inline]
//     pub fn random_challenge(&mut self) -> &Vec<F> {
//         let field_distr: FieldUniformSampler<F> = FieldUniformSampler::new();
//         self.challenge = (&mut self.randomness)
//             .sample_iter(field_distr)
//             .take(self.vp.num_rows)
//             .collect();
//         &self.challenge
//     }

//     /// tensor challenge
//     pub fn random_tensor(&mut self) -> Vec<F> {
//         assert!(self.vp.num_rows.is_power_of_two());
//         let tensor_len = self.vp.num_rows.ilog2() as usize;
//         let field_distr: FieldUniformSampler<F> = FieldUniformSampler::new();
//         let tensor: Vec<F> = (&mut self.randomness)
//             .sample_iter(field_distr)
//             .take(tensor_len)
//             .collect();
//         self.challenge = lagrange_basis(&tensor);
//         tensor
//     }

//     /// generate random queries
//     #[inline]
//     pub fn random_queries(&mut self) -> &Vec<usize> {
//         // rename variables for convenience
//         let num_queries = self.num_query();
//         let codeword_len = self.vp.code.codeword_len();

//         // generate a random set of queries or a set of full queries
//         if num_queries < codeword_len {
//             let index_distr: Uniform<usize> = Uniform::new(0, self.vp.code.codeword_len());
//             self.queries = (&mut self.randomness)
//                 .sample_iter(index_distr)
//                 .take(num_queries)
//                 .collect();
//         } else {
//             // in toy examples, num_queries > codeword_len may happen
//             // if so, shorten the queries into queries of all columns
//             self.queries = (0..codeword_len).collect::<Vec<usize>>();
//         }
//         &self.queries
//     }

//     /// receive the answer which is a message, and then
//     /// encode the answer into a codeword
//     #[inline]
//     pub fn receive_answer(&mut self, answer: &[F]) {
//         // input check
//         assert!(answer.len() == self.vp.code.message_len());
//         self.answer = answer.to_vec();
//         // encode the answer
//         self.answer.resize(self.vp.code.codeword_len(), F::ZERO);
//         self.vp.code.encode(&mut self.answer);
//     }

//     /// check the answer
//     #[inline]
//     pub fn check_answer(&mut self, merkle_paths: &[H::Output], columns: &[F]) -> bool {
//         // input check
//         assert!(self.challenge.len() == self.vp.num_rows);
//         assert!(columns.len() == self.queries.len() * self.vp.num_rows);
//         assert!(merkle_paths.len() == self.queries.len() * (self.root.depth + 1));

//         // check merkle
//         let check_merkel = self.check_merkle(merkle_paths, columns);
//         // check consistency
//         let check_consistency = self.check_consistency(columns);
//         check_merkel && check_consistency
//     }

//     /// check the hash of column is the same as the merkle leave
//     /// check the merkle path is consistent with the merkle root
//     #[inline]
//     fn check_merkle(&self, merkle_paths: &[H::Output], columns: &[F]) -> bool {
//         let mut check = true;
//         let mut hasher = H::new();
//         columns
//             .chunks_exact(self.vp.num_rows)
//             .zip(merkle_paths.chunks_exact(self.root.depth + 1))
//             .zip(&self.queries)
//             .for_each(|((column, hashes), column_idx)| {
//                 // check the hash of column is the same as the merkle leave
//                 column
//                     .iter()
//                     .for_each(|item| hasher.update_string(item.to_string()));
//                 let leaf = hasher.output_reset();

//                 // check the merkle path is consistent with the merkle root
//                 check = (leaf == hashes[0])
//                     & MerkleTree::<H>::check(self.root.root, *column_idx, hashes);
//             });
//         check
//     }

//     /// check the consistency of entry of answers with the product of challenge and column, at the given indexes
//     #[inline]
//     fn check_consistency(&self, columns: &[F]) -> bool {
//         let mut check = true;
//         columns
//             .chunks_exact(self.vp.num_rows)
//             .zip(&self.queries)
//             .for_each(|(column, idx)| {
//                 assert!(column.len() == self.vp.num_rows);
//                 let product = column
//                     .iter()
//                     .zip(&self.challenge)
//                     .map(|(x0, x1)| *x0 * x1)
//                     .fold(F::ZERO, |acc, x| acc + x);
//                 if product != self.answer[*idx] {
//                     check = false
//                 };
//             });
//         check
//     }

//     /// decompose a evaluation point x into two tensor q1, q2 that
//     /// f(x) = q1 M q2 where M is the committed matrix
//     #[inline]
//     pub fn tensor_decompose(&mut self, point: &[F]) -> Vec<F> {
//         let left_point_len = self.vp.num_rows.ilog2() as usize;
//         let right_point_len = self.vp.code.message_len().ilog2() as usize;
//         assert!(left_point_len + right_point_len == point.len());

//         self.challenge = lagrange_basis(&point[right_point_len..]);

//         self.residual_tensor = lagrange_basis(&point[..right_point_len]);

//         assert!(self.challenge.len() == self.vp.num_rows);

//         assert!(self.residual_tensor.len() == self.vp.code.message_len());

//         self.challenge.clone()
//     }

//     /// compute the residual product
//     pub fn residual_product(&self) -> F {
//         self.answer
//             .iter()
//             .zip(&self.residual_tensor)
//             .map(|(x0, x1)| *x0 * x1)
//             .fold(F::ZERO, |acc, add| acc + add)
//     }
// }
