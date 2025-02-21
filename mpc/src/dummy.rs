//! Implementation of a dummy MPC backend.

use algebra::{Field, U64FieldEval};

use crate::error::MPCErr;
use crate::MPCBackend;

/// Dummy MPC secret share (storing plain value).
#[derive(Debug, Clone, Copy)]
struct DummyShare {
    value: u64,
}

struct DummyBackend<const P: u64> {}

impl<const P: u64> MPCBackend for DummyBackend<P> {
    type Sharing = DummyShare;
    type RandomField = u64;

    fn party_id(&self) -> u32 {
        0
    }

    fn num_parties(&self) -> u32 {
        0
    }

    fn num_threshold(&self) -> u32 {
        0
    }

    fn neg(&mut self, a: DummyShare) -> Result<DummyShare, MPCErr> {
        Ok(DummyShare {
            value: U64FieldEval::<P>::neg(a.value),
        })
    }

    fn add(&mut self, a: DummyShare, b: DummyShare) -> Result<DummyShare, MPCErr> {
        Ok(DummyShare {
            value: U64FieldEval::<P>::add(a.value, b.value),
        })
    }

    fn sub(&mut self, a: DummyShare, b: DummyShare) -> Result<DummyShare, MPCErr> {
        Ok(DummyShare {
            value: U64FieldEval::<P>::sub(a.value, b.value),
        })
    }

    fn mul(&mut self, a: DummyShare, b: DummyShare) -> Result<DummyShare, MPCErr> {
        Ok(DummyShare {
            value: U64FieldEval::<P>::mul(a.value, b.value),
        })
    }

    fn mul_const(&mut self, a: DummyShare, b: u64) -> Result<DummyShare, MPCErr> {
        Ok(DummyShare {
            value: U64FieldEval::<P>::mul(a.value, b),
        })
    }

    fn mul_batch(
        &mut self,
        a: Vec<DummyShare>,
        b: Vec<DummyShare>,
    ) -> Result<Vec<DummyShare>, MPCErr> {
        let mut res = Vec::new();
        if a.len() != b.len() {
            return Err(MPCErr::InvalidOperation(
                "batch operations length mismatch".to_string(),
            ));
        }
        for i in 0..a.len() {
            res.push(Self::mul(self, a[i], b[i])?);
        }
        Ok(res)
    }

    fn inner_product(
        &mut self,
        a: Vec<Self::Sharing>,
        b: Vec<Self::Sharing>,
    ) -> Result<Self::Sharing, crate::error::MPCErr> {
        let mut res = DummyShare { value: 0 };
        for i in 0..a.len() {
            let mul_result = Self::mul(self, a[i], b[i])?;
            res = Self::add(self, res, mul_result)?;
        }
        Ok(res)
    }

    fn inner_product_const(
        &mut self,
        a: Vec<Self::Sharing>,
        b: Vec<u64>,
    ) -> Result<Self::Sharing, crate::error::MPCErr> {
        let mut res = DummyShare { value: 0 };
        for i in 0..a.len() {
            let mul_const_result = Self::mul_const(self, a[i], b[i])?;
            res = Self::add(self, res, mul_const_result)?;
        }
        Ok(res)
    }

    fn double(&mut self, a: DummyShare) -> Result<DummyShare, MPCErr> {
        Self::mul_const(self, a, 2)
    }

    fn input(&mut self, value: Option<u64>, party_id: u32) -> Result<DummyShare, MPCErr> {
        match value {
            Some(v) => Ok(DummyShare { value: v }),
            None => Err(MPCErr::InvalidOperation("input value is None".to_string())),
        }
    }

    fn reveal(&mut self, a: DummyShare, party_id: u32) -> Result<Option<u64>, MPCErr> {
        Ok(Some(a.value))
    }

    fn reveal_to_all(&mut self, a: DummyShare) -> Result<u64, MPCErr> {
        Ok(a.value)
    }

    fn rand_coin(&mut self) -> u64 {
        0
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
        let neg = backend.neg(a).unwrap();
        let result = backend.reveal_to_all(neg).unwrap();
        assert_eq!(result, U64FieldEval::<P>::neg(233));
    }

    #[test]
    fn test_add() {
        let mut backend = DummyBackend::<P> {};
        let a = backend.input(Some(10), 0).unwrap();
        let b = backend.input(Some(20), 0).unwrap();
        let add_result = backend.add(a, b).unwrap();
        let result = backend.reveal_to_all(add_result).unwrap();
        assert_eq!(result, U64FieldEval::<P>::add(10, 20));
    }

    #[test]
    fn test_sub() {
        let mut backend = DummyBackend::<P> {};
        let a = backend.input(Some(10), 0).unwrap();
        let b = backend.input(Some(20), 0).unwrap();
        let sub_result = backend.sub(a, b).unwrap();
        let result = backend.reveal_to_all(sub_result).unwrap();
        assert_eq!(result, U64FieldEval::<P>::sub(10, 20));
    }

    #[test]
    fn test_mul() {
        let mut backend = DummyBackend::<P> {};
        let a = backend.input(Some(10), 0).unwrap();
        let b = backend.input(Some(20), 0).unwrap();
        let neg_b = backend.neg(b).unwrap();
        let mul_result = backend.mul(a, neg_b).unwrap();
        let result = backend.reveal_to_all(mul_result).unwrap();
        assert_eq!(result, U64FieldEval::<P>::mul(10, P - 20));
    }

    #[test]
    fn test_mul_const() {
        let mut backend = DummyBackend::<P> {};
        let a = backend.input(Some(10), 0).unwrap();
        let b = 20;
        let mul_const_result = backend.mul_const(a, b).unwrap();
        let result = backend.reveal_to_all(mul_const_result).unwrap();
        assert_eq!(result, U64FieldEval::<P>::mul(10, 20));
    }

    #[test]
    fn test_mul_batch() {
        let mut backend = DummyBackend::<P> {};
        let a = vec![
            backend.input(Some(10), 0).unwrap(),
            backend.input(Some(20), 0).unwrap(),
        ];
        let b = vec![
            backend.input(Some(30), 0).unwrap(),
            backend.input(Some(40), 0).unwrap(),
        ];
        let result = backend.mul_batch(a, b).unwrap();
        let result_values: Vec<u64> = result
            .into_iter()
            .map(|share| backend.reveal_to_all(share).unwrap())
            .collect();
        assert_eq!(result_values[0], U64FieldEval::<P>::mul(10, 30));
        assert_eq!(result_values[1], U64FieldEval::<P>::mul(20, 40));
    }

    #[test]
    fn test_inner_product() {
        let mut backend = DummyBackend::<P> {};
        let a = vec![
            backend.input(Some(1), 0).unwrap(),
            backend.input(Some(2), 0).unwrap(),
            backend.input(Some(3), 0).unwrap(),
        ];
        let b = vec![
            backend.input(Some(4), 0).unwrap(),
            backend.input(Some(5), 0).unwrap(),
            backend.input(Some(6), 0).unwrap(),
        ];
        let result = backend.inner_product(a, b).unwrap();
        let result_value = backend.reveal_to_all(result).unwrap();
        assert_eq!(
            result_value,
            U64FieldEval::<P>::add(
                U64FieldEval::<P>::add(U64FieldEval::<P>::mul(1, 4), U64FieldEval::<P>::mul(2, 5)),
                U64FieldEval::<P>::mul(3, 6)
            )
        );
    }

    #[test]
    fn test_inner_product_const() {
        let mut backend = DummyBackend::<P> {};
        let a = vec![
            backend.input(Some(1), 0).unwrap(),
            backend.input(Some(2), 0).unwrap(),
            backend.input(Some(3), 0).unwrap(),
        ];
        let b = vec![4, 5, 6];
        let result = backend.inner_product_const(a, b).unwrap();
        let result_value = backend.reveal_to_all(result).unwrap();
        assert_eq!(
            result_value,
            U64FieldEval::<P>::add(
                U64FieldEval::<P>::add(U64FieldEval::<P>::mul(1, 4), U64FieldEval::<P>::mul(2, 5)),
                U64FieldEval::<P>::mul(3, 6)
            )
        );
    }
}
