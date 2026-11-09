use std::ptr;

use primus_modulus::BarrettModulus;
use primus_poly::DcrtPolynomial;

use super::BfvCollectiveError;

// A nonzero-sized stable object is used for local instance identity. Receivers
// rebind wire payloads through their own plan; identities are never serialized.
pub(super) struct Binding {
    _identity: u8,
}

impl Binding {
    pub(super) const fn new() -> Self {
        Self { _identity: 0 }
    }
}

/// An opaque public mathematical contribution bound to one local setup/round.
/// Exporting it does not reveal private native key column storage.
pub struct BfvCollectiveContribution<'a> {
    pub(super) binding: &'a Binding,
    pub(super) residues: Vec<u64>,
}
impl BfvCollectiveContribution<'_> {
    /// Canonical modulus-major message payload, for authenticated transport.
    #[must_use]
    pub fn as_residues(&self) -> &[u64] {
        &self.residues
    }

    /// Transfers the canonical public payload to the authenticated transport.
    /// The receiving setup must check and bind these residues to its own round.
    #[must_use]
    pub fn into_residues(self) -> Vec<u64> {
        self.residues
    }
}

/// A public sum of messages. The protocol must enforce unique authenticated
/// owners; this arithmetic owner enforces only binding and the declared count.
pub struct BfvCollectiveAggregate<'a> {
    binding: &'a Binding,
    moduli: &'a [BarrettModulus<u64>],
    n: usize,
    pub(super) expected: usize,
    count: usize,
    residues: Vec<u64>,
}
impl<'a> BfvCollectiveAggregate<'a> {
    pub(super) fn new(
        binding: &'a Binding,
        n: usize,
        moduli: &'a [BarrettModulus<u64>],
        len: usize,
        expected: usize,
    ) -> Result<Self, BfvCollectiveError> {
        if expected == 0 {
            return Err(BfvCollectiveError::Count);
        }
        Ok(Self {
            binding,
            moduli,
            n,
            expected,
            count: 0,
            residues: vec![0; len],
        })
    }

    /// Adds one already checked same-setup contribution, rejecting before writes.
    pub fn add(
        &mut self,
        message: &BfvCollectiveContribution<'_>,
    ) -> Result<(), BfvCollectiveError> {
        if !ptr::eq(self.binding, message.binding) {
            return Err(BfvCollectiveError::Binding);
        }
        if self.count == self.expected {
            return Err(BfvCollectiveError::Count);
        }
        let poly_len = self.n * self.moduli.len();
        for (out, input) in self
            .residues
            .chunks_exact_mut(poly_len)
            .zip(message.residues.chunks_exact(poly_len))
        {
            DcrtPolynomial(out).add_assign(&DcrtPolynomial(input), self.n, self.moduli);
        }
        self.count += 1;
        Ok(())
    }
    pub(super) fn finish(self, binding: &Binding) -> Result<Vec<u64>, BfvCollectiveError> {
        if !ptr::eq(self.binding, binding) {
            return Err(BfvCollectiveError::Binding);
        }
        if self.count != self.expected {
            return Err(BfvCollectiveError::Count);
        }
        Ok(self.residues)
    }
}
pub(super) fn validate_payload(
    n: usize,
    moduli: &[u64],
    values: &[u64],
    len: usize,
) -> Result<(), BfvCollectiveError> {
    let poly_len = n * moduli.len();
    if values.len() != len || !len.is_multiple_of(poly_len) {
        return Err(BfvCollectiveError::Payload);
    }
    for poly in values.chunks_exact(poly_len) {
        for (limb, &q) in poly.chunks_exact(n).zip(moduli) {
            if limb.iter().any(|&x| x >= q) {
                return Err(BfvCollectiveError::Payload);
            }
        }
    }
    Ok(())
}
