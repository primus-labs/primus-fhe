//! PIOP for Bit Decomposition (which could also be used for Range Check)
//! Define the structures required in SNARKs for Bit Decomposition
//! The prover wants to convince that the decomposition of an element into some bits on a power-of-two base.
//! * base (denoted by B): the power-of-two base used in bit decomposition
//! * base_len: the length of base, i.e. log_2(base)
//! * bits_len (denoted by l): the length of decomposed bits
//!
//! Given M instances of bit decomposition to be proved, d and each bit of d, i.e. (d_0, ..., d_l),
//! the main idea of this IOP is to prove:
//! For x \in \{0, 1\}^l
//! 1. d(x) = \sum_{i=0}^{log M - 1} B^i d_i(x) => can be reduced to the evaluation of a random point
//! 2. For every i \in \[l\]: \prod_{k = 0}^B (d_i(x) - k) = 0 =>
//!     a) each of which can be reduced to prove the following sum
//!        $\sum_{x \in \{0, 1\}^\log M} eq(u, x) \cdot [\prod_{k=0}^B (d_i(x) - k)] = 0$
//!        where u is the common random challenge from the verifier, used to instantiate every sum,
//!     b) and then, it can be proved with the sumcheck protocol where the maximum variable-degree is B + 1.
//!
//! The second part consists of l sumcheck protocols which can be combined into one giant sumcheck via random linear combination,
//! then the resulting purported sum is:
//! $\sum_{x \in \{0, 1\}^\log M} \sum_{i = 0}^{l-1} r_i \cdot eq(u, x) \cdot [\prod_{k=0}^B (d_i(x) - k)] = 0$
//! where r_i (for i = 0..l) are sampled from the verifier.
use algebra::{DenseMultilinearExtension, Field, MultilinearExtension};
use std::marker::PhantomData;
use std::rc::Rc;

use crate::sumcheck::prover::ProverMsg;

use crate::sumcheck::MLSumcheck;
use crate::utils::{eval_identity_function, gen_identity_evaluations};
use algebra::{FieldUniformSampler, ListOfProductsOfPolynomials, PolynomialInfo};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use rand_distr::Distribution;

/// SNARKs for bit decomposition
pub struct BitDecomposition<F: Field>(PhantomData<F>);

/// proof generated by prover
pub struct BitDecompositionProof<F: Field> {
    pub(crate) sumcheck_msg: Vec<ProverMsg<F>>,
}

/// subclaim returned to verifier
pub struct BitDecompositionSubClaim<F: Field> {
    /// r
    pub randomness: Vec<F>,
    /// reduced point from the sumcheck protocol
    pub point: Vec<F>,
    /// expected value returned in sumcheck
    pub expected_evaluation: F,
}

/// Stores the parameters used for bit decomposation and every instance of decomposed bits,
/// and the batched polynomial used for the sumcheck protocol.
///
/// It is required to decompose over a power-of-2 base.
/// The resulting decomposed bits are used as the prover key.
pub struct DecomposedBits<F: Field> {
    /// base
    pub base: F,
    /// the length of base, i.e. log_2(base)
    pub base_len: u32,
    /// the length of decomposed bits
    pub bits_len: u32,
    /// number of variables of every polynomial
    pub num_vars: usize,
    /// batched plain deomposed bits, each of which corresponds to one bit decomposisiton instance
    pub instances: Vec<Vec<Rc<DenseMultilinearExtension<F>>>>,
}

/// Stores the parameters used for bit decomposation.
///
/// * It is required to decompose over a power-of-2 base.
///
/// These parameters are used as the verifier key.
#[derive(Clone)]
pub struct DecomposedBitsInfo<F: Field> {
    /// base
    pub base: F,
    /// the length of base, i.e. log_2(base)
    pub base_len: u32,
    /// the length of decomposed bits (denoted by l)
    pub bits_len: u32,
    /// number of variables of every polynomial
    pub num_vars: usize,
    /// number of instances
    pub num_instances: usize,
}

impl<F: Field> DecomposedBits<F> {
    #[inline]
    /// Extract the information of decomposed bits for verification
    pub fn info(&self) -> DecomposedBitsInfo<F> {
        DecomposedBitsInfo {
            base: self.base,
            base_len: self.base_len,
            bits_len: self.bits_len,
            num_vars: self.num_vars,
            num_instances: self.instances.len(),
        }
    }

    /// Initiate the polynomial used for sumcheck protocol
    #[inline]
    pub fn new(base: F, base_len: u32, bits_len: u32, num_vars: usize) -> Self {
        DecomposedBits {
            base,
            base_len,
            bits_len,
            num_vars,
            instances: Vec::new(),
        }
    }

    /// Initiate the polynomial from the given info used for sumcheck protocol
    #[inline]
    pub fn from_info(info: &DecomposedBitsInfo<F>) -> Self {
        DecomposedBits {
            base: info.base,
            base_len: info.base_len,
            bits_len: info.bits_len,
            num_vars: info.num_vars,
            instances: Vec::with_capacity(info.num_instances),
        }
    }

    #[inline]
    /// Add one bit decomposition instance, meaning to add l sumcheck protocols.
    /// * decomposed_bits: store each bit
    pub fn add_decomposed_bits_instance(
        &mut self,
        decomposed_bits: &[Rc<DenseMultilinearExtension<F>>],
    ) {
        assert_eq!(decomposed_bits.len(), self.bits_len as usize);
        for bit in decomposed_bits {
            assert_eq!(bit.num_vars, self.num_vars);
        }
        self.instances.push(decomposed_bits.to_vec());
    }

    /// Use the base defined in this instance to perform decomposition over the input value.
    /// Then add the result into this instance, meaning to add l sumcheck protocols.
    /// * decomposed_bits: store each bit
    #[inline]
    pub fn add_value_instance(&mut self, value: &DenseMultilinearExtension<F>) {
        assert_eq!(self.num_vars, value.num_vars);
        self.instances
            .push(value.get_decomposed_mles(self.base_len, self.bits_len));
    }

    #[inline]
    /// Batch all the sumcheck protocol, each corresponding to range-check one single bit.
    /// * randomness: randomness used to linearly combine bits_len * num_instances sumcheck protocols
    /// * u is the common random challenge from the verifier, used to instantiate every sum.
    pub fn randomized_sumcheck(&self, randomness: &[F], u: &[F]) -> ListOfProductsOfPolynomials<F> {
        assert_eq!(
            randomness.len(),
            self.instances.len() * self.bits_len as usize
        );
        assert_eq!(u.len(), self.num_vars);

        let mut poly = <ListOfProductsOfPolynomials<F>>::new(self.num_vars);
        let identity_func_at_u = Rc::new(gen_identity_evaluations(u));
        let base = 1 << self.base_len;

        let mut r_iter = randomness.iter();
        for instance in &self.instances {
            // For every bit, the reduced sum is $\sum_{x \in \{0, 1\}^\log M} eq(u, x) \cdot [\prod_{k=0}^B (d_i(x) - k)] = 0$
            // and the added product is r_i \cdot eq(u, x) \cdot [\prod_{k=0}^B (d_i(x) - k)] with the corresponding randomness
            for bit in instance {
                let mut product: Vec<_> = Vec::with_capacity(base + 1);
                let mut op_coefficient: Vec<_> = Vec::with_capacity(base + 1);
                product.push(Rc::clone(&identity_func_at_u));
                op_coefficient.push((F::ONE, F::ZERO));

                let mut minus_k = F::ZERO;
                for _ in 0..base {
                    product.push(Rc::clone(bit));
                    op_coefficient.push((F::ONE, minus_k));
                    minus_k -= F::ONE;
                }
                poly.add_product_with_linear_op(product, &op_coefficient, *r_iter.next().unwrap());
            }
        }
        poly
    }
}

impl<F: Field> BitDecompositionSubClaim<F> {
    /// verify the subclaim
    ///
    /// # Argument
    ///   
    /// * `d_val` stores each value to be decomposed
    /// * `d_bits` stores the decomposed bits for each value in d_val
    /// * `u` is the common random challenge from the verifier, used to instantiate every sum.
    pub fn verify_subclaim(
        &self,
        d_val: &[Rc<DenseMultilinearExtension<F>>],
        d_bits: &[&Vec<Rc<DenseMultilinearExtension<F>>>],
        u: &[F],
        decomposed_bits_info: &DecomposedBitsInfo<F>,
    ) -> bool {
        assert_eq!(d_val.len(), decomposed_bits_info.num_instances);
        assert_eq!(d_bits.len(), decomposed_bits_info.num_instances);
        assert_eq!(u.len(), decomposed_bits_info.num_vars);

        let d_val_at_point: Vec<_> = d_val.iter().map(|val| val.evaluate(&self.point)).collect();
        let d_bits_at_point: Vec<Vec<_>> = d_bits
            .iter()
            .map(|bits| bits.iter().map(|bit| bit.evaluate(&self.point)).collect())
            .collect();

        // base_pow = [1, B, ..., B^{l-1}]
        let mut base_pow = vec![F::ONE; decomposed_bits_info.bits_len as usize];
        base_pow.iter_mut().fold(F::ONE, |acc, pow| {
            *pow *= acc;
            acc * decomposed_bits_info.base
        });

        // check 1: d[point] = \sum_{i=0}^len B^i \cdot d_i[point] for every instance
        if !d_val_at_point
            .iter()
            .zip(d_bits_at_point.iter())
            .all(|(val, bits)| {
                *val == bits
                    .iter()
                    .zip(base_pow.iter())
                    .fold(F::ZERO, |acc, (bit, pow)| acc + *pow * *bit)
            })
        {
            return false;
        }

        // check 2: expected value returned in sumcheck
        // each instance contributes value: eq(u, x) \cdot \sum_{i = 0}^{l-1} r_i \cdot [\prod_{k=0}^B (d_i(x) - k)] =? expected_evaluation
        let mut evaluation = F::zero();
        let mut r = self.randomness.iter();
        d_bits_at_point.iter().for_each(|bits| {
            bits.iter().for_each(|bit| {
                let mut prod = *r.next().unwrap();
                let mut minus_k = F::ZERO;
                for _ in 0..(1 << decomposed_bits_info.base_len) {
                    prod *= *bit + minus_k;
                    minus_k -= F::ONE;
                }
                evaluation += prod;
            })
        });
        self.expected_evaluation == evaluation * eval_identity_function(u, &self.point)
    }
}

impl<F: Field> BitDecomposition<F> {
    /// Prove bit decomposition given the decomposed bits as prover key.
    pub fn prove(decomposed_bits: &DecomposedBits<F>, u: &[F]) -> BitDecompositionProof<F> {
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::prove_as_subprotocol(&mut fs_rng, decomposed_bits, u)
    }

    /// Prove bit decomposition given the decomposed bits as prover key.
    /// This function does the same thing as `prove`, but it uses a `Fiat-Shamir RNG` as the transcript/to generate the
    /// verifier challenges.
    pub fn prove_as_subprotocol(
        fs_rng: &mut impl RngCore,
        decomposed_bits: &DecomposedBits<F>,
        u: &[F],
    ) -> BitDecompositionProof<F> {
        let num_bits = decomposed_bits.instances.len() * decomposed_bits.bits_len as usize;
        // TODO sample randomness via Fiat-Shamir RNG
        // batch `len_bits` sumcheck protocols into one with random linear combination
        let sampler = <FieldUniformSampler<F>>::new();
        let randomness: Vec<_> = (0..num_bits).map(|_| sampler.sample(fs_rng)).collect();
        let poly = decomposed_bits.randomized_sumcheck(&randomness, u);
        BitDecompositionProof {
            sumcheck_msg: MLSumcheck::prove_as_subprotocol(fs_rng, &poly)
                .expect("bit decomposition failed")
                .0,
        }
    }

    /// Verify bit decomposition given the basic information of decomposed bits as verifier key.
    pub fn verifier(
        proof: &BitDecompositionProof<F>,
        decomposed_bits_info: &DecomposedBitsInfo<F>,
    ) -> BitDecompositionSubClaim<F> {
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::verifier_as_subprotocol(&mut fs_rng, proof, decomposed_bits_info)
    }

    /// Verify bit decomposition given the basic information of decomposed bits as verifier key.
    /// This function does the same thing as `prove`, but it uses a `Fiat-Shamir RNG` as the transcript/to generate the
    /// verifier challenges.
    pub fn verifier_as_subprotocol(
        fs_rng: &mut impl RngCore,
        proof: &BitDecompositionProof<F>,
        decomposed_bits_info: &DecomposedBitsInfo<F>,
    ) -> BitDecompositionSubClaim<F> {
        let num_bits = decomposed_bits_info.num_instances * decomposed_bits_info.bits_len as usize;
        // TODO sample randomness via Fiat-Shamir RNG
        // batch `len_bits` sumcheck protocols into one with random linear combination
        let sampler = <FieldUniformSampler<F>>::new();
        let randomness: Vec<_> = (0..num_bits).map(|_| sampler.sample(fs_rng)).collect();
        let poly_info = PolynomialInfo {
            max_multiplicands: 1 + (1 << decomposed_bits_info.base_len),
            num_variables: decomposed_bits_info.num_vars,
        };
        let subclaim =
            MLSumcheck::verify_as_subprotocol(fs_rng, &poly_info, F::ZERO, &proof.sumcheck_msg)
                .expect("bit decomposition verification failed");
        BitDecompositionSubClaim {
            randomness,
            point: subclaim.point,
            expected_evaluation: subclaim.expected_evaluations,
        }
    }
}
