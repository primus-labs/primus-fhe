//! Interactive Proof Protocol used for Multilinear Sumcheck
// It is derived from https://github.com/arkworks-rs/sumcheck/blob/master/src/ml_sumcheck/protocol/mod.rs.

use algebra::{Field, ListOfProductsOfPolynomials, PolynomialInfo, Random};
use prover::{ProverMsg, ProverState};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::marker::PhantomData;
use verifier::SubClaim;

pub mod prover;
pub mod verifier;

pub struct IPForMLSumcheck<F: Field> {
    #[doc(hidden)]
    _marker: PhantomData<F>,
}

/// Sumcheck for products of multilinear polynomial
pub struct MLSumcheck<F: Field>(#[doc(hidden)] PhantomData<F>);

/// proof generated by prover
pub type Proof<F> = Vec<ProverMsg<F>>;

impl<F: Field + Random> MLSumcheck<F> {
    /// Extract sum from the proof
    pub fn extract_sum(proof: &Proof<F>) -> F {
        proof[0].evaluations[0] + proof[0].evaluations[1]
    }

    /// Generate proof of the sum of polynomial over {0, 1}^`num_vars`
    ///
    /// The polynomial is represented by a list of products of polynomials along with its coefficient that is meant to be added together.
    ///
    /// This data structure of the polynomial is a list of list of `(coefficient, DenseMultilinearExtension)`.
    /// * Number of products n = `polynomial.products.len()`,
    /// * Number of multiplicands of ith product m_i = `polynomial.products[i].1.len()`,
    /// * Coefficient of ith product c_i = `polynomial.products[i].0`
    ///
    /// The resulting polynomial is
    ///
    /// $$\sum_{i=0}^{n}C_i\cdot\prod_{j=0}^{m_i}P_{ij}$$
    pub fn prove(
        polynomial: &ListOfProductsOfPolynomials<F>,
    ) -> Result<Proof<F>, crate::error::Error> {
        // TODO switch to the Fiat-Shamir RNG
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::prove_as_subprotocol(&mut fs_rng, polynomial).map(|r| r.0)
    }

    /// This function does the same thing as `prove`, but it uses a `Fiat-Shamir RNG` as the transcript/to generate the
    /// verifier challenges. Additionally, it returns the prover's state in addition to the proof.
    /// Both of these allow this sumcheck to be better used as a part of a larger protocol.
    pub fn prove_as_subprotocol(
        fs_rng: &mut impl RngCore,
        polynomial: &ListOfProductsOfPolynomials<F>,
    ) -> Result<(Proof<F>, ProverState<F>), crate::error::Error> {
        // TODO update Fiat-Shamir RNG using polynomial.info()

        let mut prover_state = IPForMLSumcheck::prover_init(polynomial);
        let mut verifier_msg = None;
        let mut prover_msgs = Vec::with_capacity(polynomial.num_variables);
        for _ in 0..polynomial.num_variables {
            let prover_msg = IPForMLSumcheck::prove_round(&mut prover_state, &verifier_msg);
            // TODO update Fiat-Shamir RNG using prover's message
            prover_msgs.push(prover_msg);
            verifier_msg = Some(IPForMLSumcheck::sample_round(fs_rng));
        }
        prover_state
            .randomness
            .push(verifier_msg.unwrap().randomness);
        Ok((prover_msgs, prover_state))
    }

    pub fn verify(
        polynomial_info: &PolynomialInfo,
        claimed_sum: F,
        proof: &Proof<F>,
    ) -> Result<SubClaim<F>, crate::Error> {
        // TODO switch to the Fiat-Shamir RNG
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::verify_as_subprotocol(&mut fs_rng, polynomial_info, claimed_sum, proof)
    }

    /// This function does the same thing as `verify`, but it uses a `Fiat-Shamir RNG`` as the transcript to generate the
    /// verifier challenges. This allows this sumcheck to be used as a part of a larger protocol.
    pub fn verify_as_subprotocol(
        fs_rng: &mut impl RngCore,
        polynomial_info: &PolynomialInfo,
        claimed_sum: F,
        proof: &Proof<F>,
    ) -> Result<SubClaim<F>, crate::Error> {
        // TODO update Fiat-Shamir RNG using polynomial.info()
        let mut verifier_state = IPForMLSumcheck::verifier_init(polynomial_info);
        for i in 0..polynomial_info.num_variables {
            let prover_msg = proof.get(i).expect("proof is incomplete");
            // TODO update Fiat-Shamir RNG using prover's message

            let _verifier_msg =
                IPForMLSumcheck::verify_round((*prover_msg).clone(), &mut verifier_state, fs_rng);
        }

        IPForMLSumcheck::check_and_generate_subclaim(verifier_state, claimed_sum)
    }
}
