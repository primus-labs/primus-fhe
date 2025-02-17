#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]
//! This crate provides backend for various MPC operations over a network.

pub mod dummy;
pub mod error;
// pub mod bgw;
// pub mod dn;

/// Unique id for a secret share
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MPCId(pub usize);

/// MPC backend trait
pub trait MPCBackend {
    /// Get the party id.
    fn id(&self) -> MPCId;

    /// Get the number of parties.
    fn num_parties(&self) -> u32;

    /// Get the number of threshold.
    fn num_threshold(&self) -> u32;

    /// Get the field modulus.
    fn field_modulus(&self) -> u64;

    /// Add two secret shares.
    fn add(&mut self, a: MPCId, b: MPCId) -> Result<MPCId, error::MPCErr>;

    /// Double a secret share.
    fn double(&mut self, a: MPCId) -> Result<MPCId, error::MPCErr>;

    /// Subtract two secret shares.
    fn sub(&mut self, a: MPCId, b: MPCId) -> Result<MPCId, error::MPCErr>;

    /// Negate a secret share.
    fn neg(&mut self, a: MPCId) -> Result<MPCId, error::MPCErr>;

    /// Multiply two secret shares.
    fn mul(&mut self, a: MPCId, b: MPCId) -> Result<MPCId, error::MPCErr>;

    /// Multiply a secret share with a constant.
    fn mul_const(&mut self, a: MPCId, b: u64) -> Result<MPCId, error::MPCErr>;

    /// Input a secret value from a party (party_id). Inputs from all other parties are omitted.
    fn input(&mut self, value: Option<u64>, party_id: u32) -> Result<MPCId, error::MPCErr>;

    /// Output a secret value to a party (party_id). Other parties get a dummy value.
    fn reveal(&mut self, a: MPCId, party_id: u32) -> Result<u64, error::MPCErr>;

    /// Output a secret value to all parties.
    fn reveal_to_all(&mut self, a: MPCId) -> Result<u64, error::MPCErr>;

    /// Generate a random coin/value (more than two parties, Fiat-Shamir not feasible?).
    fn rand_coin(&mut self) -> u64;
}
