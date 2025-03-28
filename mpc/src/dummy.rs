//! Implementation of a dummy MPC backend.

use crate::error::MPCErr;
use crate::{MPCBackend, MPCResult};
use algebra::modulus::BarrettModulus;
use algebra::{Field, U64FieldEval};
use std::time::Duration;

/// Dummy MPC secret share (storing plain value).
#[derive(Debug, Clone, Copy, Default)]
pub struct DummyShare {
    value: u64,
}

/// Dummy MPC backend.
pub struct DummyBackend<const P: u64> {}

impl<const P: u64> MPCBackend for DummyBackend<P> {
    type Sharing = DummyShare;
    type Modulus = BarrettModulus<u64>;

    fn party_id(&self) -> u32 {
        0
    }

    fn num_parties(&self) -> u32 {
        1
    }

    fn num_threshold(&self) -> u32 {
        0
    }

    fn modulus(&self) -> Self::Modulus {
        U64FieldEval::<P>::MODULUS
    }

    fn field_modulus_value(&self) -> u64 {
        P
    }

    fn neg(&self, a: DummyShare) -> DummyShare {
        DummyShare {
            value: U64FieldEval::<P>::neg(a.value),
        }
    }

    fn add(&self, a: DummyShare, b: DummyShare) -> DummyShare {
        DummyShare {
            value: U64FieldEval::<P>::add(a.value, b.value),
        }
    }

    fn double(&self, a: DummyShare) -> DummyShare {
        DummyShare {
            value: U64FieldEval::<P>::double(a.value),
        }
    }

    fn add_const(&self, a: Self::Sharing, b: u64) -> Self::Sharing {
        DummyShare {
            value: U64FieldEval::<P>::add(a.value, b),
        }
    }

    fn sub(&self, a: DummyShare, b: DummyShare) -> DummyShare {
        DummyShare {
            value: U64FieldEval::<P>::sub(a.value, b.value),
        }
    }

    fn mul_const(&self, a: DummyShare, b: u64) -> DummyShare {
        DummyShare {
            value: U64FieldEval::<P>::mul(a.value, b),
        }
    }

    fn mul_local(&self, a: Self::Sharing, b: Self::Sharing) -> Self::Sharing {
        DummyShare {
            value: U64FieldEval::<P>::mul(a.value, b.value),
        }
    }

    fn mul(&mut self, a: DummyShare, b: DummyShare) -> MPCResult<DummyShare> {
        Ok(DummyShare {
            value: U64FieldEval::<P>::mul(a.value, b.value),
        })
    }

    fn mul_element_wise(
        &mut self,
        a: &[DummyShare],
        b: &[DummyShare],
    ) -> MPCResult<Vec<DummyShare>> {
        if a.len() != b.len() {
            return Err(MPCErr::InvalidOperation(
                "batch operations length mismatch".to_string(),
            ));
        }
        Ok(a.iter()
            .zip(b.iter())
            .map(|(a, b)| DummyShare {
                value: U64FieldEval::<P>::mul(a.value, b.value),
            })
            .collect())
    }

    fn double_mul_element_wise(
        &mut self,
        a: &[DummyShare],
        b: &[DummyShare],
    ) -> MPCResult<Vec<DummyShare>> {
        if a.len() != b.len() {
            return Err(MPCErr::InvalidOperation(
                "batch operations length mismatch".to_string(),
            ));
        }
        Ok(a.iter()
            .zip(b.iter())
            .map(|(a, b)| DummyShare {
                value: U64FieldEval::<P>::mul(a.value, b.value),
            })
            .collect())
    }

    fn inner_product(&mut self, a: &[DummyShare], b: &[DummyShare]) -> MPCResult<Self::Sharing> {
        if a.len() != b.len() {
            return Err(MPCErr::InvalidOperation(
                "batch operations length mismatch".to_string(),
            ));
        }
        let value = a.iter().zip(b.iter()).fold(0u64, |acc, (x, y)| {
            U64FieldEval::<P>::mul_add(x.value, y.value, acc)
        });

        Ok(DummyShare { value })
    }

    fn inner_product_const(&mut self, a: &[DummyShare], b: &[u64]) -> Self::Sharing {
        let value = a.iter().zip(b.iter()).fold(0u64, |acc, (x, y)| {
            U64FieldEval::<P>::mul_add(x.value, *y, acc)
        });

        DummyShare { value }
    }

    fn input(&mut self, value: Option<u64>, _party_id: u32) -> MPCResult<DummyShare> {
        match value {
            Some(v) => Ok(DummyShare { value: v }),
            None => Err(MPCErr::InvalidOperation("input value is None".to_string())),
        }
    }

    fn input_slice(
        &mut self,
        values: Option<&[u64]>,
        _batch_size: usize,
        _party_id: u32,
    ) -> MPCResult<Vec<DummyShare>> {
        Ok(values
            .unwrap()
            .iter()
            .map(|v| DummyShare { value: *v })
            .collect())
    }

    fn input_slice_with_different_party_ids(
        &mut self,
        values: &[Option<u64>],
        party_ids: &[u32],
    ) -> MPCResult<Vec<DummyShare>> {
        Ok(values
            .iter()
            .zip(party_ids.iter())
            .map(|(v, _)| DummyShare {
                value: v.unwrap_or(0),
            })
            .collect())
    }

    fn reveal(&mut self, a: DummyShare, _party_id: u32) -> MPCResult<Option<u64>> {
        Ok(Some(a.value))
    }

    fn reveal_slice(&mut self, a: &[DummyShare], party_id: u32) -> MPCResult<Vec<Option<u64>>> {
        Ok(a.iter()
            .map(|share| self.reveal(*share, party_id).unwrap())
            .collect())
    }

    fn reveal_to_all(&mut self, a: DummyShare) -> MPCResult<u64> {
        Ok(a.value)
    }

    fn reveal_slice_to_all(&mut self, a: &[Self::Sharing]) -> MPCResult<Vec<u64>> {
        Ok(a.iter().map(|share| share.value).collect())
    }

    fn reveal_slice_degree_2t_to_all(&mut self, shares: &[Self::Sharing]) -> MPCResult<Vec<u64>> {
        Ok(shares.iter().map(|share| share.value).collect())
    }

    fn shared_rand_coin(&mut self) -> u64 {
        0
    }

    fn shared_rand_field_element(&mut self) -> u64 {
        0
    }

    fn shared_rand_field_elements(&mut self, destination: &mut [u64]) {
        destination.fill(0);
    }

    fn create_random_elements(&mut self, batch_size: usize) -> Vec<Self::Sharing> {
        vec![DummyShare { value: 0 }; batch_size]
    }

    fn ntt_sharing_poly_inplace(&self, _poly: &mut [Self::Sharing]) {
        unimplemented!()
    }

    fn ntt_poly_inplace(&self, _poly: &mut [u64]) {
        unimplemented!()
    }

    fn mul_element_wise_z2k(&mut self, a: &[u64], b: &[u64]) -> Vec<u64> {
        unimplemented!()
    }
    fn init_z2k_triples_from_files(&mut self) {
        unimplemented!()
    }
    fn reveal_slice_to_all_z2k(&mut self, shares: &[u64]) -> Vec<u64> {
        unimplemented!()
    }
    fn test_open_secrets_z2k(
        &mut self,
        reconstructor_id: u32,
        degree: u32,
        shares: &[u64],
        broadcast_result: bool,
    ) -> Option<Vec<u64>> {
        unimplemented!()
    }

    fn reveal_slice_z2k(&mut self, shares: &[u64], party_id: u32) -> Vec<Option<u64>> {
        unimplemented!()
    }

    fn input_slice_z2k(
        &mut self,
        values: Option<&[u64]>,
        batch_size: usize,
        party_id: u32,
    ) -> Vec<u64> {
        unimplemented!()
    }

    fn add_z2k_slice(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        unimplemented!()
    }

    fn sub_z2k_slice(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        unimplemented!()
    }

    fn double_z2k_slice(&self, a: &[u64]) -> Vec<u64> {
        unimplemented!()
    }
    fn shamir_secrets_to_additive_secrets(&mut self, shares: &[Self::Sharing]) -> Vec<u64> {
        unimplemented!()
    }

    fn add_z2k_const(&mut self, a: u64, b: u64) -> u64 {
        unimplemented!()
    }

    fn sub_z2k_const(&mut self, a: u64, b: u64) -> u64 {
        unimplemented!()
    }
    fn sub_additive_const_p(&mut self, a: u64, b: u64) -> u64 {
        unimplemented!()
    }
    fn mul_additive_const_p(&mut self, a: u64, b: u64) -> u64 {
        unimplemented!()
    }
    fn inner_product_additive_const_p(&mut self, a: &[u64], b: &[u64]) -> u64 {
        unimplemented!()
    }
    fn sends_slice_to_all_parties(
        &mut self,
        values: Option<&[u64]>,
        batch_size: usize,
        party_id: u32,
    ) -> Vec<u64> {
        unimplemented!()
    }

    fn input_slice_with_prg_z2k(
        &mut self,
        values: Option<&[u64]>,
        batch_size: usize,
        party_id: u32,
    ) -> Vec<u64> {
        unimplemented!()
    }
    fn input_slice_with_prg(
        &mut self,
        values: Option<&[u64]>,
        batch_size: usize,
        party_id: u32,
    ) -> MPCResult<Vec<Self::Sharing>> {
        unimplemented!()
    }

    fn total_mul_triple_duration(&mut self) -> Duration {
        unimplemented!()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    const P: u64 = 998244353;

    #[test]
    fn test_neg() {
        let mut backend = DummyBackend::<P> {};
        let a = backend.input(Some(233), 0).unwrap();
        let neg = backend.neg(a);
        let result = backend.reveal_to_all(neg).unwrap();
        assert_eq!(result, U64FieldEval::<P>::neg(233));
    }

    #[test]
    fn test_add() {
        let mut backend = DummyBackend::<P> {};
        let a = backend.input(Some(10), 0).unwrap();
        let b = backend.input(Some(20), 0).unwrap();
        let add_result = backend.add(a, b);
        let result = backend.reveal_to_all(add_result).unwrap();
        assert_eq!(result, U64FieldEval::<P>::add(10, 20));
    }

    #[test]
    fn test_sub() {
        let mut backend = DummyBackend::<P> {};
        let a = backend.input(Some(10), 0).unwrap();
        let b = backend.input(Some(20), 0).unwrap();
        let sub_result = backend.sub(a, b);
        let result = backend.reveal_to_all(sub_result).unwrap();
        assert_eq!(result, U64FieldEval::<P>::sub(10, 20));
    }

    #[test]
    fn test_mul() {
        let mut backend = DummyBackend::<P> {};
        let a = backend.input(Some(10), 0).unwrap();
        let b = backend.input(Some(20), 0).unwrap();
        let neg_b = backend.neg(b);
        let mul_result = backend.mul(a, neg_b).unwrap();
        let result = backend.reveal_to_all(mul_result).unwrap();
        assert_eq!(result, U64FieldEval::<P>::mul(10, P - 20));
    }

    #[test]
    fn test_mul_const() {
        let mut backend = DummyBackend::<P> {};
        let a = backend.input(Some(10), 0).unwrap();
        let b = 20;
        let mul_const_result = backend.mul_const(a, b);
        let result = backend.reveal_to_all(mul_const_result).unwrap();
        assert_eq!(result, U64FieldEval::<P>::mul(10, 20));
    }

    #[test]
    fn test_mul_batch() -> MPCResult<()> {
        let mut backend = DummyBackend::<P> {};
        let a = vec![backend.input(Some(10), 0)?, backend.input(Some(20), 0)?];
        let b = vec![backend.input(Some(30), 0)?, backend.input(Some(40), 0)?];
        let result = backend.mul_element_wise(&a, &b)?;
        let result_values: Vec<u64> = result
            .into_iter()
            .map(|share| backend.reveal_to_all(share).unwrap())
            .collect();
        assert_eq!(result_values[0], U64FieldEval::<P>::mul(10, 30));
        assert_eq!(result_values[1], U64FieldEval::<P>::mul(20, 40));
        Ok(())
    }

    #[test]
    fn test_inner_product() -> MPCResult<()> {
        let mut backend = DummyBackend::<P> {};
        let a = vec![
            backend.input(Some(1), 0)?,
            backend.input(Some(2), 0)?,
            backend.input(Some(3), 0)?,
        ];
        let b = vec![
            backend.input(Some(4), 0)?,
            backend.input(Some(5), 0)?,
            backend.input(Some(6), 0)?,
        ];
        let result = backend.inner_product(&a, &b)?;
        let result_value = backend.reveal_to_all(result)?;
        assert_eq!(
            result_value,
            U64FieldEval::<P>::add(
                U64FieldEval::<P>::add(U64FieldEval::<P>::mul(1, 4), U64FieldEval::<P>::mul(2, 5)),
                U64FieldEval::<P>::mul(3, 6)
            )
        );
        Ok(())
    }

    #[test]
    fn test_inner_product_const() -> MPCResult<()> {
        let mut backend = DummyBackend::<P> {};
        let a = vec![
            backend.input(Some(1), 0)?,
            backend.input(Some(2), 0)?,
            backend.input(Some(3), 0)?,
        ];
        let b = vec![4, 5, 6];
        let result = backend.inner_product_const(&a, &b);
        let result_value = backend.reveal_to_all(result)?;
        assert_eq!(
            result_value,
            U64FieldEval::<P>::add(
                U64FieldEval::<P>::add(U64FieldEval::<P>::mul(1, 4), U64FieldEval::<P>::mul(2, 5)),
                U64FieldEval::<P>::mul(3, 6)
            )
        );
        Ok(())
    }
}
