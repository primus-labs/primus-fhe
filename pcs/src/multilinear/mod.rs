/// Brakedown Multilinear Polynomial Commitment
pub mod brakedown;

use algebra::{Field, MultilinearExtension};
use rand::RngCore;
use std::fmt::Debug;

type Point<F, P> = <P as MultilinearExtension<F>>::Point;

/// Polymomial Commitment Scheme
pub trait PolynomialCommitmentScheme<F: Field, S>: Clone + Debug {
    /// prover's parameters
    type ProverParam: Clone + Debug + Default;
    /// verifier's parameters
    type VerifierParam: Clone + Debug + Default;
    /// polynomial to commit
    type Polynomial: MultilinearExtension<F>;
    /// commitment
    type Commitment: Clone + Debug + Default;
    /// Proof
    type Proof: Clone + Debug + Default;

    /// setup
    fn setup(
        poly_size: usize,
        spec: S,
        rng: impl RngCore,
    ) -> (Self::ProverParam, Self::VerifierParam);

    /// commit
    fn commit(pp: &Self::ProverParam, poly: &Self::Polynomial) -> Self::Commitment;

    /// open
    fn open(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        commit: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
    ) -> Self::Proof;

    /// verify
    fn verify(
        vp: &Self::VerifierParam,
        commit: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        proof: &Self::Proof,
    );
}
