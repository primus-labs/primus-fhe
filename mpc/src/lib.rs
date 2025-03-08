#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]
//! This crate provides backend for various MPC operations over a network.

pub mod dn;
pub mod dummy;
pub mod error;

use std::fmt::Debug;

use algebra::reduce::FieldReduce;
pub use dn::DNBackend;
pub use dummy::DummyBackend;

type MPCResult<T> = Result<T, error::MPCErr>;

/// MPC backend trait
pub trait MPCBackend {
    /// Generic secret sharing type.
    type Sharing: Clone + Copy + Default + Debug;

    /// Generic field modulus type.
    type Modulus: FieldReduce<u64>;

    /// Get the party id.
    fn party_id(&self) -> u32;

    /// Get the number of parties.
    fn num_parties(&self) -> u32;

    /// Get the number of threshold.
    fn num_threshold(&self) -> u32;

    /// Get the field modulus.
    fn modulus(&self) -> Self::Modulus;

    /// Get the field modulus.
    fn field_modulus_value(&self) -> u64;

    /// Negate a secret share.
    fn neg(&mut self, a: Self::Sharing) -> Self::Sharing;

    /// Add two secret shares.
    fn add(&mut self, a: Self::Sharing, b: Self::Sharing) -> Self::Sharing;

    /// Add two secret shares.
    fn add_const(&mut self, a: Self::Sharing, b: u64) -> Self::Sharing;

    /// Subtract two secret shares.
    fn sub(&mut self, a: Self::Sharing, b: Self::Sharing) -> Self::Sharing;

    /// Multiply a secret share with a constant.
    fn mul_const(&mut self, a: Self::Sharing, b: u64) -> Self::Sharing;

    /// Multiply two secret shares locally.
    fn mul_local(&self, a: Self::Sharing, b: Self::Sharing) -> Self::Sharing;

    /// Multiply two secret shares.
    fn mul(&mut self, a: Self::Sharing, b: Self::Sharing) -> MPCResult<Self::Sharing>;

    /// Multiply batch of secret shares.
    fn mul_element_wise(
        &mut self,
        a: &[Self::Sharing],
        b: &[Self::Sharing],
    ) -> MPCResult<Vec<Self::Sharing>>;

    /// Multiply batch of secret shares use double random.
    fn double_mul_element_wise(
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

    /// Input several secret values from a party (party_id). Inputs from all other parties are omitted.
    fn input_slice(
        &mut self,
        values: Option<&[u64]>,
        batch_size: usize,
        party_id: u32,
    ) -> MPCResult<Vec<Self::Sharing>>;

    /// Input several secret values from different parties.
    fn input_slice_with_different_party_ids(
        &mut self,
        values: &[Option<u64>],
        party_ids: &[u32],
    ) -> MPCResult<Vec<Self::Sharing>>;

    /// Output a secret value to a party (party_id). Other parties get a dummy value.
    fn reveal(&mut self, share: Self::Sharing, party_id: u32) -> MPCResult<Option<u64>>;

    /// Output a slice of secret values to a party (party_id). Other parties get dummy values.
    fn reveal_slice(
        &mut self,
        shares: &[Self::Sharing],
        party_id: u32,
    ) -> MPCResult<Vec<Option<u64>>>;

    /// Output a secret value to all parties.
    fn reveal_to_all(&mut self, share: Self::Sharing) -> MPCResult<u64>;

    /// Output a slice of secret values to all parties.
    fn reveal_slice_to_all(&mut self, shares: &[Self::Sharing]) -> MPCResult<Vec<u64>>;

    /// Reveal a slice of secret values to all parties.
    fn reveal_slice_degree_2t_to_all(&mut self, shares: &[Self::Sharing]) -> MPCResult<Vec<u64>>;

    /// Generate a random value over `u64`.
    fn shared_rand_coin(&mut self) -> u64;

    /// Generate a random value over a specific field.
    fn shared_rand_field_element(&mut self) -> u64;

    /// Generate random values over a specific field.
    fn shared_rand_field_elements(&mut self, destination: &mut [u64]);

    /// Generates a batch of random elements.
    fn create_random_elements(&mut self, batch_size: usize) -> Vec<Self::Sharing>;

    /// Transform a polynomial to NTT domain.
    fn ntt_sharing_poly_inplace(&self, poly: &mut [Self::Sharing]);

    /// Transform a polynomial to NTT domain.
    fn ntt_poly_inplace(&self, poly: &mut [u64]);
}
