//! polynomial commitment scheme

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

/// mulilinear polynomial commitment
pub mod multilinear;
/// utils, mainly used to implement linear time encodable code now
pub mod utils;

use algebra::{utils::Transcript, AbstractExtensionField, Field, MultilinearExtension};
use serde::{Deserialize, Serialize};

// type Point<F, P> = <P as MultilinearExtension<F>>::Point;

/// Polymomial Commitment Scheme
pub trait PolynomialCommitmentScheme<F: Field, EF: AbstractExtensionField<F>, S> {
    /// System parameters
    type Parameters: Default;
    /// Polynomial to commit
    type Polynomial: MultilinearExtension<F>;
    /// Extension field polynomial to commit
    type EFPolynomial: MultilinearExtension<EF>;
    /// Commitment
    type Commitment: Serialize + for<'de> Deserialize<'de>;
    /// Auxiliary state of the commitment, output by the `commit` phase.
    type CommitmentState;
    /// Auxiliary state of the commitment, output by the `commit` phase.
    type CommitmentStateEF;
    /// Opening Proof
    type Proof: Serialize + for<'de> Deserialize<'de> + Default + Clone;
    /// Opening Proof for EF
    type ProofEF: Serialize + for<'de> Deserialize<'de> + Default + Clone;
    /// Point
    type Point;

    /// The Setup phase.
    fn setup(num_vars: usize, code_spec: Option<S>) -> Self::Parameters;

    /// The Commit phase.
    fn commit(
        pp: &Self::Parameters,
        poly: &Self::Polynomial,
    ) -> (Self::Commitment, Self::CommitmentState);

    /// The Commit phase for extension field.
    fn commit_ef(
        pp: &Self::Parameters,
        poly: &Self::EFPolynomial,
    ) -> (Self::Commitment, Self::CommitmentStateEF);

    /// The Opening phase.
    fn open(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        state: &Self::CommitmentState,
        points: &[Self::Point],
        trans: &mut Transcript<EF>,
    ) -> Self::Proof;

    /// The Opening phase for EF.
    fn open_ef(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        state: &Self::CommitmentStateEF,
        points: &[Self::Point],
        trans: &mut Transcript<EF>,
    ) -> Self::ProofEF;

    /// The batch opening phase.
    fn batch_open(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        state: &Self::CommitmentState,
        batch_points: &[Vec<Self::Point>],
        trans: &mut Transcript<EF>,
    ) -> Vec<Self::Proof>;

    /// The batch opening phase for EF.
    fn batch_open_ef(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        state: &Self::CommitmentStateEF,
        batch_points: &[Vec<Self::Point>],
        trans: &mut Transcript<EF>,
    ) -> Vec<Self::ProofEF>;

    /// The Verification phase.
    fn verify(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        points: &[Self::Point],
        eval: Self::Point,
        proof: &Self::Proof,
        trans: &mut Transcript<EF>,
    ) -> bool;

    /// The Verification phase for EF.
    fn verify_ef(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        points: &[Self::Point],
        eval: Self::Point,
        proof: &Self::ProofEF,
        trans: &mut Transcript<EF>,
    ) -> bool;

    /// The batch verification phase.
    fn batch_verify(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        batch_points: &[Vec<Self::Point>],
        evals: &[Self::Point],
        proofs: &[Self::Proof],
        trans: &mut Transcript<EF>,
    ) -> bool;

    /// The batch verification phase for EF.
    fn batch_verify_ef(
        pp: &Self::Parameters,
        commitment: &Self::Commitment,
        batch_points: &[Vec<Self::Point>],
        evals: &[Self::Point],
        proofs: &[Self::ProofEF],
        trans: &mut Transcript<EF>,
    ) -> bool;
}
