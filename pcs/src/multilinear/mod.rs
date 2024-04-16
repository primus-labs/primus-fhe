/// Brakedown Multilinear Polynomial Commitment
pub mod brakedown;

use algebra::{Field, MultilinearExtension};

use rand::RngCore;
use std::fmt::Debug;
///
//pub type Point<F, P> = <P as MultilinearExtension<F>>::Point;
//pub type Point<F> = <DenseMultilinearExtension<F> as MultilinearExtension<F>>::Point;
///
pub trait PolynomialCommitmentScheme<F: Field, S>: Clone + Debug {
    /// prover's parameters
    type ProverParam: Clone + Debug;
    /// verifier's parameters
    type VerifierParam: Clone + Debug;
    /// polynomial to commit
    type Polynomial: MultilinearExtension<F>;
    /// commitment
    type Commitment: Clone + Debug + Default; // + AsRef<[Self::CommitmentChunk]>;
    ///
    type CommitmentChunk: Clone + Debug + Default;

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
        comm: &Self::Commitment,
        //point: &Point<F, Self::Polynomial>,
        eval: &F,
    );

    /// verify
    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        //point: &Point<F, Self::Polynomial>,
        eval: &F,
    );
}
