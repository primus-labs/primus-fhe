//! polynomial commitment scheme

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

/// mulilinear polynomial commitment
pub mod multilinear;
/// utils, mainly used to implement linear time encodable code now
pub mod utils;

use algebra::{utils::Transcript, Field, MultilinearExtension};
use rand::{CryptoRng, Rng};

type Point<F, P> = <P as MultilinearExtension<F>>::Point;

/// Polymomial Commitment Scheme
pub trait PolynomialCommitmentScheme<F: Field, S> {
    /// System parameters
    type Parameters;
    /// polynomial to commit
    type Polynomial: MultilinearExtension<F>;
    /// commitment
    type Commitment;
    /// Auxiliary state of the commitment, output by the `commit` phase.
    type CommitmentState;
    /// Opening Proof
    type Proof;

    /// setup
    fn setup(
        num_vars: usize,
        code_spec: Option<S>,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Self::Parameters;

    /// commit
    fn commit(
        pp: &Self::Parameters,
        poly: &Self::Polynomial,
    ) -> (Self::Commitment, Self::CommitmentState);

    /// open
    fn open(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        state: &Self::CommitmentState,
        point: &Point<F, Self::Polynomial>,
        trans: &mut Transcript<F>,
    ) -> Self::Proof;

    /// verify
    fn verify(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: F,
        proof: &Self::Proof,
        trans: &mut Transcript<F>,
    ) -> bool;
}
