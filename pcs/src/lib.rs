//! polynomial commitment scheme

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

/// mulilinear polynomial commitment
pub mod multilinear;
/// utils, mainly used to implement linear time encodable code now
pub mod utils;

use algebra::{utils::Transcript, Field, MultilinearExtensionBase};

// type Point<F, P> = <P as MultilinearExtension<F>>::Point;

/// Polymomial Commitment Scheme
pub trait PolynomialCommitmentScheme<F: Field, S> {
    /// System parameters
    type Parameters;
    /// polynomial to commit
    type Polynomial: MultilinearExtensionBase<F>;
    /// commitment
    type Commitment;
    /// Auxiliary state of the commitment, output by the `commit` phase.
    type CommitmentState;
    /// Opening Proof
    type Proof;
    /// Point
    type Point;

    /// The Setup phase.
    fn setup(num_vars: usize, code_spec: Option<S>) -> Self::Parameters;

    /// The Commit phase.
    fn commit(
        pp: &Self::Parameters,
        poly: &Self::Polynomial,
    ) -> (Self::Commitment, Self::CommitmentState);

    /// The Opening phase.
    fn open(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        state: &Self::CommitmentState,
        points: &[Self::Point],
        trans: &mut Transcript<F>,
    ) -> Self::Proof;

    /// The Verification phase.
    fn verify(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        points: &[Self::Point],
        eval: Self::Point,
        proof: &Self::Proof,
        trans: &mut Transcript<F>,
    ) -> bool;
}
