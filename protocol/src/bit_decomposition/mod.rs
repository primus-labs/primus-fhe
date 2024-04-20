//! SNARKs for Bit Decomposition (which could also be used for Range Check)
//! 
pub mod data_structures;
use crate::sumcheck::MLSumcheck;
use algebra::{
    DenseMultilinearExtension, Field, FieldUniformSampler, ListOfProductsOfPolynomials,
    PolynomialInfo,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use rand_distr::Distribution;
use std::rc::Rc;

pub use data_structures::{
    BitDecomposition, BitDecompositionProof, BitDecompositionSubClaim, DecomposedBits,
    DecomposedBitsInfo,
};

/// Generate MLE of the ideneity function eq(u,x) for x \in \{0, 1\}^dim
pub fn gen_identity_evaluations<F: Field>(u: &[F]) -> DenseMultilinearExtension<F> {
    let dim = u.len();
    let mut evaluations: Vec<_> = (0..(1 << dim)).map(|_| F::ZERO).collect();
    evaluations[0] = F::ONE;
    for i in 0..dim {
        // The index represents a point in {0,1}^`num_vars` in little endian form.
        // For example, `0b1011` represents `P(1,1,0,1)`
        let u_i_rev = u[dim - i - 1];
        for b in (0..(1 << i)).rev() {
            evaluations[(b << 1) + 1] = evaluations[b] * u_i_rev;
            evaluations[b << 1] = evaluations[b] * (F::ONE - u_i_rev);
        }
    }
    DenseMultilinearExtension::from_evaluations_vec(dim, evaluations)
}

/// Evaluate eq(u, v) = \prod_i (u_i * v_i + (1 - u_i) * (1 - v_i))
pub fn eval_identity_function<F: Field>(u: &[F], v: &[F]) -> F {
    assert_eq!(u.len(), v.len());
    let mut evaluation = F::ONE;
    for (u_i, v_i) in u.iter().zip(v) {
        evaluation *= *u_i * *v_i + (F::ONE - *u_i) * (F::ONE - *v_i);
    }
    evaluation
}

/// Batch the sumcheck for range check that's meant to prove each bit \in base
pub fn randomize_sumcheck<F: Field>(
    decomposed_bits: &DecomposedBits<F>,
    randomness: &[F],
    u: &[F],
) -> ListOfProductsOfPolynomials<F> {
    let dim = u.len();
    let len: usize = decomposed_bits.bits_len as usize;
    let base: usize = 1 << decomposed_bits.base_len;
    let d_i = &decomposed_bits.decomposed_bits;
    for bit in d_i {
        assert_eq!(dim, bit.num_vars);
    }
    let identity_at_u = Rc::new(gen_identity_evaluations(u));

    let mut poly = <ListOfProductsOfPolynomials<F>>::new(dim);
    for i in 0..len {
        let mut product: Vec<_> = Vec::with_capacity(base + 1);
        let mut op_coefficient: Vec<_> = Vec::with_capacity(base + 1);
        product.push(Rc::clone(&identity_at_u));
        op_coefficient.push((F::ONE, F::ZERO));

        let mut minus_j_as_field = F::ZERO;
        for _ in 0..base {
            product.push(Rc::clone(&d_i[i]));
            op_coefficient.push((F::ONE, minus_j_as_field));
            minus_j_as_field -= F::ONE;
        }
        poly.add_product_with_linear_op(product, &op_coefficient, randomness[i]);
    }
    poly
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
    /// verifier challenges. Additionally, it returns the prover's state in addition to the proof.
    /// Both of these allow this sumcheck to be better used as a part of a larger protocol.
    pub fn prove_as_subprotocol(
        fs_rng: &mut impl RngCore,
        decomposed_bits: &DecomposedBits<F>,
        u: &[F],
    ) -> BitDecompositionProof<F> {
        let len_bits = decomposed_bits.bits_len as usize;
        // TODO sample randomness via Fiat-Shamir RNG
        // batch `len_bits` sumcheck protocols into one with random linear combination
        let sampler = <FieldUniformSampler<F>>::new();
        let randomness: Vec<_> = (0..len_bits).map(|_| sampler.sample(fs_rng)).collect();
        let poly = randomize_sumcheck(decomposed_bits, &randomness, u);
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
    /// verifier challenges. Additionally, it returns the prover's state in addition to the proof.
    /// Both of these allow this sumcheck to be better used as a part of a larger protocol.
    pub fn verifier_as_subprotocol(
        fs_rng: &mut impl RngCore,
        proof: &BitDecompositionProof<F>,
        decomposed_bits_info: &DecomposedBitsInfo<F>,
    ) -> BitDecompositionSubClaim<F> {
        let len_bits = decomposed_bits_info.len_bits as usize;
        // TODO sample randomness via Fiat-Shamir RNG
        // batch `len_bits` sumcheck protocols into one with random linear combination
        let sampler = <FieldUniformSampler<F>>::new();
        let randomness: Vec<_> = (0..len_bits).map(|_| sampler.sample(fs_rng)).collect();
        let poly_info = PolynomialInfo {
            max_multiplicands: 1 + (1 << decomposed_bits_info.base_bits),
            num_variables: decomposed_bits_info.num_variables,
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

#[cfg(test)]
mod test {
    use crate::bit_decomposition::{eval_identity_function, gen_identity_evaluations};
    use algebra::{
        derive::{Field, Prime},
        FieldUniformSampler, MultilinearExtension,
    };
    use rand::thread_rng;
    use rand_distr::Distribution;

    #[derive(Field, Prime)]
    #[modulus = 132120577]
    pub struct Fp32(u32);
    // field type
    type FF = Fp32;

    #[test]
    fn test_gen_identity_evaluations() {
        let sampler = <FieldUniformSampler<FF>>::new();
        let mut rng = thread_rng();
        let dim = 10;
        let u: Vec<_> = (0..dim).map(|_| sampler.sample(&mut rng)).collect();

        let identity_at_u = gen_identity_evaluations(&u);

        let v: Vec<_> = (0..dim).map(|_| sampler.sample(&mut rng)).collect();

        assert_eq!(eval_identity_function(&u, &v), identity_at_u.evaluate(&v));
    }
}
