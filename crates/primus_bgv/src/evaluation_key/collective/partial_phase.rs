//! Physical phase products for callers that supply their own opening policy.
use primus_data::{Data, DataMut};
use primus_poly::DcrtPolynomial;

use crate::{BgvCiphertext, BgvClient};

use super::super::error::validate_level;
use super::{
    messages::{BgvCollectiveError, validate_values},
    secret_prefix,
};

impl BgvClient<'_> {
    /// Writes only this owner's native partial phase `c1*s_i`, without c0.
    /// No privacy flooding, roster check or one-use authorization is implied.
    /// This is a physical phase contribution, so it is not divided by the
    /// ciphertext's plaintext correction factor. The caller authenticates that
    /// factor with the complete ciphertext and applies its inverse once, after
    /// recovering the aggregate centered phase modulo p.
    /// # Correctness
    /// Input uses this exact actual secret and context/NTT convention.
    /// # Errors
    /// Rejects an unprepared level, wrong complete lengths or noncanonical input
    /// before writes. Allocates nothing. Arithmetic panic may partially overwrite
    /// output; no secret/noise distribution requirement is imposed by this product.
    pub fn partial_phase_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &self,
        input: &BgvCiphertext<A>,
        level: usize,
        output: &mut DcrtPolynomial<B>,
    ) -> Result<(), BgvCollectiveError> {
        validate_level(self.context, level)?;
        input
            .validate_binding(self.context, level)
            .map_err(|_| BgvCollectiveError::Binding)?;
        let n = self.context.parameters().poly_length().get();
        let base = self.context.base_q(level);
        let len = n * base.moduli_count();
        validate_values(n, base, input.as_ref(), 2 * len)?;
        if output.as_ref().len() != len {
            return Err(BgvCollectiveError::Length {
                expected: len,
                actual: output.as_ref().len(),
            });
        }
        output.as_mut().copy_from_slice(&input.as_ref()[len..]);
        output.mul_assign(
            &DcrtPolynomial(secret_prefix(self.secret_key(), len)),
            n,
            base.moduli(),
        );
        Ok(())
    }
}
