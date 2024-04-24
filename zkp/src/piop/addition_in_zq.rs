//! Define the structures required in SNARKs for Addition in Zq
use std::marker::PhantomData;
use std::rc::Rc;

use crate::sumcheck::prover::ProverMsg;
use super::bit_decomposition::{BitDecompositionProof, BitDecompositionSubClaim, DecomposedBits, DecomposedBitsInfo};
use crate::utils::eval_identity_function;
use crate::piop::BitDecomposition;

use algebra::{DenseMultilinearExtension, Field, ListOfProductsOfPolynomials, MultilinearExtension, PolynomialInfo};
use crate::utils::gen_identity_evaluations;
use crate::sumcheck::MLSumcheck;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;


/// SNARKs for addition in Zq, i.e. a + b = c (mod Zq)
pub struct AdditionInZq<F: Field>(#[doc(hidden)] PhantomData<F>);

/// proof generated by prover
pub struct AdditionInZqProof<F: Field> {
    /// batched rangecheck proof for a, b, c \in Zq
    pub rangecheck_msg: BitDecompositionProof<F>,
    /// sumcheck proof for \sum_{x} eq(u, x) * k(x) * (1-k(x)) = 0, i.e. k(x)\in\{0,1\}^l
    pub sumcheck_msg: Vec<ProverMsg<F>>,
}

/// subclaim returned to verifier
pub struct AdditionInZqSubclaim<F: Field> {
    /// rangecheck subclaim for a, b, c \in Zq
    pub(crate) rangecheck_subclaim: BitDecompositionSubClaim<F>,
    /// subcliam for \sum_{x} eq(u, x) * k(x) * (1-k(x)) = 0
    pub sumcheck_point: Vec<F>,
    /// expected value returned in the last round of the sumcheck
    pub sumcheck_expected_evaluations: F,
}

/// 
pub struct AdditionInZqInstance<F: Field> {
    /// modular in addition
    pub q: F,
    ///
    pub num_vars: usize,
    /// 
    pub abc: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// 
    pub k: Rc<DenseMultilinearExtension<F>>,
    /// 
    pub abc_bits: DecomposedBits<F>,
}

/// 
pub struct AdditionInZqInstanceInfo<F: Field> {
    /// modular in addition
    pub q: F,
    /// 
    pub decomposed_bits_info: DecomposedBitsInfo<F>,
}

impl<F: Field> AdditionInZqInstance<F> {
    #[inline]
    /// Extract the information of addition in zq for verification
    pub fn info(&self) -> AdditionInZqInstanceInfo<F> {
        AdditionInZqInstanceInfo {
            q: self.q,
            decomposed_bits_info: self.abc_bits.info()
        }
    }

    /// 
    pub fn from_vec(
        abc: Vec<Rc<DenseMultilinearExtension<F>>>, 
        k: &Rc<DenseMultilinearExtension<F>>,
        q: F, base: F, base_len: u32, bits_len: u32,
    ) -> Self {
        let num_vars = k.num_vars;
        assert_eq!(abc.len(), 3);
        for x in &abc {
            assert_eq!(x.num_vars, num_vars);
        }

        let abc_bits = abc.iter().map(|x| x.get_decomposed_mles(base_len, bits_len)).collect();
        Self {
            q,
            num_vars,
            abc,
            k: Rc::clone(k),
            abc_bits: DecomposedBits {
                base,
                base_len,
                bits_len,
                num_vars,
                instances: abc_bits,
            }
        }
    } 

    ///
    pub fn from_slice(
        abc: &Vec<Rc<DenseMultilinearExtension<F>>>, 
        k: &Rc<DenseMultilinearExtension<F>>,
        q: F, base: F, base_len: u32, bits_len: u32,
    ) -> Self {
        let num_vars = k.num_vars;
        assert_eq!(abc.len(), 3);
        for x in abc {
            assert_eq!(x.num_vars, num_vars);
        }

        let abc_bits = abc.iter().map(|x| x.get_decomposed_mles(base_len, bits_len)).collect();
        Self {
            q,
            num_vars,
            abc: abc.clone(),
            k: Rc::clone(k),
            abc_bits: DecomposedBits {
                base,
                base_len,
                bits_len,
                num_vars,
                instances: abc_bits,
            }
        }
    }
}

impl<F: Field> AdditionInZqSubclaim<F> {
    /// verify the sumcliam
    pub fn verify_subclaim(
        &self,
        q: F,
        abc: &Vec<Rc<DenseMultilinearExtension<F>>>,
        k: &DenseMultilinearExtension<F>,
        abc_bits: &Vec<Vec<Rc<DenseMultilinearExtension<F>>>>,
        u: &[F],
        info: &AdditionInZqInstanceInfo<F>,
    ) -> bool {
        assert_eq!(abc.len(), 3);
        assert_eq!(abc_bits.len(), 3);

        // check 1: subclaim for rangecheck, i.e. a, b, c \in [Zq]
        if !self.rangecheck_subclaim.verify_subclaim(abc, abc_bits, u, &info.decomposed_bits_info) {
            return false;
        }
        
        // check 2: subclaim for sumcheck, i.e. eq(u, point) * k(point) * (1 - k(point)) = 0
        let eval_k = k.evaluate(&self.sumcheck_point);
        if eval_identity_function(u, &self.sumcheck_point) * eval_k * (F::ONE - eval_k) != self.sumcheck_expected_evaluations {
            return false;
        }

        // check 3: a(u) + b(u) = c(u) + k(u) * q
        abc[0].evaluate(u) + abc[1].evaluate(u) == abc[2].evaluate(u) + k.evaluate(u) * q
    }
}

impl<F: Field> AdditionInZq<F> {
    /// Prove addition in Zq given a, b, c, k, and the decomposed bits for a, b, and c.
    pub fn prove(
        addition_instance: &AdditionInZqInstance<F>,
        u: &[F],
    ) -> AdditionInZqProof<F> {
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::prove_as_subprotocol(&mut fs_rng, addition_instance, u)
    }

    /// Prove addition in Zq given a, b, c, k, and the decomposed bits for a, b, and c.
    /// This function does the same thing as `prove`, but it uses a `Fiat-Shamir RNG` as the transcript/to generate the
    /// verifier challenges. Additionally, it returns the prover's state in addition to the proof.
    /// Both of these allow this sumcheck to be better used as a part of a larger protocol.
    pub fn prove_as_subprotocol(
        fs_rng: &mut impl RngCore,
        addition_instance: &AdditionInZqInstance<F>,
        u: &[F],
    ) -> AdditionInZqProof<F> {
        // 1. rangecheck
        let rangecheck_msg = BitDecomposition::prove_as_subprotocol(fs_rng, &addition_instance.abc_bits, u);

        let dim = u.len();
        assert_eq!(dim, addition_instance.num_vars);
        let mut poly = <ListOfProductsOfPolynomials<F>>::new(dim);
        
        // 2. execute sumcheck for \sum_{x} eq(u, x) * k(x) * (1-k(x)) = 0, i.e. k(x)\in\{0,1\}^l
        let mut product = Vec::with_capacity(3);
        let mut op_coefficient= Vec::with_capacity(3);
        product.push(Rc::new(gen_identity_evaluations(u)));
        op_coefficient.push((F::ONE, F::ZERO));

        product.push(Rc::clone(&addition_instance.k));
        op_coefficient.push((F::ONE, F::ZERO));
        product.push(Rc::clone(&addition_instance.k));
        op_coefficient.push((-F::ONE, F::ONE));
        
        poly.add_product_with_linear_op(product, &op_coefficient, F::ONE);
        let sumcheck_proof = MLSumcheck::prove_as_subprotocol(fs_rng, &poly)
            .expect("sumcheck for addition in Zq failed");
        
        AdditionInZqProof {
            rangecheck_msg,
            sumcheck_msg: sumcheck_proof.0,
        }
    }

    /// Verify addition in Zq given the proof and the verification key for bit decomposistion
    pub fn verify (
        proof: &AdditionInZqProof<F>,
        decomposed_bits_info: &DecomposedBitsInfo<F>,
    ) -> AdditionInZqSubclaim<F> {
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::verifier_as_subprotocol(&mut fs_rng, proof, decomposed_bits_info)
    }

    /// Verify addition in Zq given the proof and the verification key for bit decomposistion
    pub fn verifier_as_subprotocol(
        fs_rng: &mut impl RngCore,
        proof: &AdditionInZqProof<F>,
        decomposed_bits_info: &DecomposedBitsInfo<F>,
    ) -> AdditionInZqSubclaim<F> {
        // TODO sample randomness via Fiat-Shamir RNG
        let rangecheck_subclaim = BitDecomposition::verifier_as_subprotocol(fs_rng, &proof.rangecheck_msg, decomposed_bits_info);
        
        // execute sumcheck for \sum_{x} eq(u, x) * k(x) * (1-k(x)) = 0, i.e. k(x)\in\{0,1\}^l
        let poly_info = PolynomialInfo {
            max_multiplicands: 3,
            num_variables: decomposed_bits_info.num_vars,
        };
        let subclaim =
            MLSumcheck::verify_as_subprotocol(fs_rng, &poly_info, F::ZERO, &proof.sumcheck_msg)
                .expect("sumcheck protocol in addition in Zq failed");
        AdditionInZqSubclaim {
            rangecheck_subclaim,
            sumcheck_point: subclaim.point,
            sumcheck_expected_evaluations: subclaim.expected_evaluations,
        }
    }
}