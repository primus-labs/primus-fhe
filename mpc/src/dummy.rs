//! Implementation of a dummy MPC backend.

use crate::error::MPCErr;
use crate::{MPCBackend, MPCId};

/// Dummy MPC secret share (storing plain value).
#[derive(Debug, Clone, Copy)]
struct DummyShare {
    value: u64,
}

/// Dummy MPC backend.
pub struct DummyBackend {
    party_id: u32,
    num_parties: u32,
    num_threshold: u32,
    field_modulus: u64,
    storage: Vec<DummyShare>,
    id_counter: usize,
}

impl DummyBackend {
    /// Create a new dummy backend.
    pub fn new(party_id: u32, num_parties: u32, num_threshold: u32, field_modulus: u64) -> Self {
        Self {
            party_id,
            num_parties,
            num_threshold,
            field_modulus,
            storage: Vec::new(),
            id_counter: 0,
        }
    }

    /// Fetch a secret share.
    pub fn fetch_share(&self, id: MPCId) -> Result<u64, MPCErr> {
        if id.0 >= self.id_counter {
            return Err(MPCErr::IdNotFound(id.0));
        }
        Ok(self.storage[id.0].value)
    }

    /// Store a secret share inside the backend.
    pub fn store_share(&mut self, value: u64) -> MPCId {
        let id = self.id_counter;
        self.id_counter += 1;
        self.storage.push(DummyShare { value });
        MPCId(id)
    }
}

impl MPCBackend for DummyBackend {
    fn id(&self) -> MPCId {
        MPCId(self.party_id as usize)
    }

    fn num_parties(&self) -> u32 {
        self.num_parties
    }

    fn num_threshold(&self) -> u32 {
        self.num_threshold
    }

    fn field_modulus(&self) -> u64 {
        self.field_modulus
    }

    fn add(&mut self, a: MPCId, b: MPCId) -> Result<MPCId, MPCErr> {
        let a = self.fetch_share(a)?;
        let b = self.fetch_share(b)?;
        Ok(self.store_share((a + b) % self.field_modulus))
    }

    fn double(&mut self, a: MPCId) -> Result<MPCId, crate::error::MPCErr> {
        let a = self.fetch_share(a)?;
        let t = a << 1;
        if t >= self.field_modulus {
            Ok(self.store_share(t - self.field_modulus))
        } else {
            Ok(self.store_share(t))
        }
    }

    fn sub(&mut self, a: MPCId, b: MPCId) -> Result<MPCId, MPCErr> {
        let a = self.fetch_share(a)?;
        let b = self.fetch_share(b)?;
        Ok(self.store_share((a + self.field_modulus - b) % self.field_modulus))
    }

    fn neg(&mut self, a: MPCId) -> Result<MPCId, crate::error::MPCErr> {
        let a = self.fetch_share(a)?;
        Ok(self.store_share(if a == 0 { 0 } else { self.field_modulus - a }))
    }

    fn mul(&mut self, a: MPCId, b: MPCId) -> Result<MPCId, MPCErr> {
        let a = self.fetch_share(a)?;
        let b = self.fetch_share(b)?;
        Ok(self.store_share((a * b) % self.field_modulus))
    }

    fn mul_const(&mut self, a: MPCId, b: u64) -> Result<MPCId, crate::error::MPCErr> {
        let a = self.fetch_share(a)?;
        Ok(self.store_share((a * b) % self.field_modulus))
    }

    fn input(&mut self, value: Option<u64>, _party_id: u32) -> Result<MPCId, MPCErr> {
        if let Some(value) = value {
            Ok(self.store_share(value))
        } else {
            todo!("get share from network")
        }
    }

    fn reveal(&mut self, a: MPCId, _party_id: u32) -> Result<u64, MPCErr> {
        self.fetch_share(a)
    }

    fn reveal_to_all(&mut self, a: MPCId) -> Result<u64, MPCErr> {
        self.fetch_share(a)
    }

    fn rand_coin(&mut self) -> u64 {
        0
    }
}
