#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]
//! This crate provides backend for various MPC operations over a network.

pub mod dummy;
pub mod error;
// pub mod bgw;
// pub mod dn;

/// MPC backend trait
pub trait MPCBackend {
    /// Get the party id.
    fn party_id(&self) -> u32;

    /// Get the number of parties.
    fn num_parties(&self) -> u32;

    /// Get the number of threshold.
    fn num_threshold(&self) -> u32;

    /// Generic secret sharing type.
    type Sharing;

    /// Negate a secret share.
    fn neg(&mut self, a: Self::Sharing) -> Result<Self::Sharing, error::MPCErr>;

    /// Add two secret shares.
    fn add(&mut self, a: Self::Sharing, b: Self::Sharing) -> Result<Self::Sharing, error::MPCErr>;

    /// Subtract two secret shares.
    fn sub(&mut self, a: Self::Sharing, b: Self::Sharing) -> Result<Self::Sharing, error::MPCErr>;

    /// Multiply a secret share with a constant.
    fn mul_const(&mut self, a: Self::Sharing, b: u64) -> Result<Self::Sharing, error::MPCErr>;

    /// Multiply two secret shares.
    fn mul(&mut self, a: Self::Sharing, b: Self::Sharing) -> Result<Self::Sharing, error::MPCErr>;

    /// Multiply batch of secret shares.
    fn mul_batch(
        &mut self,
        a: Vec<Self::Sharing>,
        b: Vec<Self::Sharing>,
    ) -> Result<Vec<Self::Sharing>, error::MPCErr>;

    /// Double a secret share.
    fn double(&mut self, a: Self::Sharing) -> Result<Self::Sharing, error::MPCErr>;

    /// Input a secret value from a party (party_id). Inputs from all other parties are omitted.
    fn input(&mut self, value: Option<u64>, party_id: u32) -> Result<Self::Sharing, error::MPCErr>;

    /// Output a secret value to a party (party_id). Other parties get a dummy value.
    fn reveal(&mut self, a: Self::Sharing, party_id: u32) -> Result<Option<u64>, error::MPCErr>;

    /// Output a secret value to all parties.
    fn reveal_to_all(&mut self, a: Self::Sharing) -> Result<u64, error::MPCErr>;

    /// Generic field type for random values.
    type RandomField;

    /// Generate a random value over a specific field.
    fn rand_coin(&mut self) -> Self::RandomField;
}
