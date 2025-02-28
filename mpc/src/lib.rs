#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]
//! This crate provides backend for various MPC operations over a network.

pub mod dn;
pub mod dummy;
pub mod error;

pub use dn::DNBackend;

type MPCResult<T> = Result<T, error::MPCErr>;

/// MPC backend trait
pub trait MPCBackend {
    /// Generic secret sharing type.
    type Sharing: Clone + Copy + Default;

    /// Generic field type for random values.
    type RandomField: Clone;

    /// Get the party id.
    fn party_id(&self) -> u32;

    /// Get the number of parties.
    fn num_parties(&self) -> u32;

    /// Get the number of threshold.
    fn num_threshold(&self) -> u32;

    /// Get the field modulus.
    fn field_modulus_value(&self) -> u64;

    /// Negate a secret share.
    fn neg(&mut self, a: Self::Sharing) -> Self::Sharing;

    /// Add two secret shares.
    fn add(&mut self, a: Self::Sharing, b: Self::Sharing) -> Self::Sharing;

    /// Subtract two secret shares.
    fn sub(&mut self, a: Self::Sharing, b: Self::Sharing) -> Self::Sharing;

    /// Multiply a secret share with a constant.
    fn mul_const(&mut self, a: Self::Sharing, b: u64) -> Self::Sharing;

    /// Multiply two secret shares.
    fn mul(&mut self, a: Self::Sharing, b: Self::Sharing) -> MPCResult<Self::Sharing>;

    /// Multiply batch of secret shares.
    fn mul_element_wise(
        &mut self,
        a: &[Self::Sharing],
        b: &[Self::Sharing],
    ) -> MPCResult<Vec<Self::Sharing>>;

    /// Inner product of two arrays of secret shares.
    fn inner_product(
        &mut self,
        a: &[Self::Sharing],
        b: &[Self::Sharing],
    ) -> MPCResult<Self::Sharing>;

    /// Inner product of an array of secret shares with an array of constants.
    fn inner_product_const(&mut self, a: &[Self::Sharing], b: &[u64]) -> Self::Sharing;

    /// Double a secret share.
    fn double(&mut self, a: Self::Sharing) -> Self::Sharing;

    /// Input a secret value from a party (party_id). Inputs from all other parties are omitted.
    fn input(&mut self, value: Option<u64>, party_id: u32) -> MPCResult<Self::Sharing>;

    /// Output a secret value to a party (party_id). Other parties get a dummy value.
    fn reveal(&mut self, a: Self::Sharing, party_id: u32) -> MPCResult<Option<u64>>;

    /// Output a secret value to all parties.
    fn reveal_to_all(&mut self, a: Self::Sharing) -> MPCResult<u64>;

    /// Generate a random value over `u64`.
    fn shared_rand_coin(&mut self) -> Self::RandomField;

    /// Generate a random value over a specific field.
    fn shared_rand_field_element(&mut self) -> u64;

    /// Generate random values over a specific field.
    fn shared_rand_field_elements(&mut self, destination: &mut [u64]);
}
