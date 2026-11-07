use std::ptr;

use primus_glwe_rns::DcrtGlweSecretKey;
use primus_poly::DcrtPolynomial;
use zeroize::Zeroizing;

use super::{
    BfvCollectiveContribution, BfvCollectiveError, BfvCollectiveRelinearizationRound1,
    EvaluationSetup,
};

/// One party's private single-use two-round state. Ephemeral storage is erased
/// on success, errors and unwind; it has no Clone/Debug/serialization interface.
pub struct BfvCollectiveRelinearizationState<'p, 'c> {
    setup: &'p EvaluationSetup<'c>,
    share: &'p DcrtGlweSecretKey<u64>,
    ephemeral: Zeroizing<Vec<u64>>,
}
impl<'p, 'c> BfvCollectiveRelinearizationState<'p, 'c> {
    pub(super) fn new(
        setup: &'p EvaluationSetup<'c>,
        share: &'p DcrtGlweSecretKey<u64>,
        ephemeral: Zeroizing<Vec<u64>>,
    ) -> Self {
        Self {
            setup,
            share,
            ephemeral,
        }
    }

    /// Consumes this private state before producing `s_i*H0+(u_i-s_i)*H1+e2`.
    /// A rejected aggregate or RNG failure does not restore the state.
    /// The protocol authenticates the frozen aggregate for this ceremony.
    pub fn round2<'r, R: rand::Rng + rand::CryptoRng>(
        mut self,
        round1: &'r BfvCollectiveRelinearizationRound1<'_, '_>,
        rng: &mut R,
    ) -> Result<BfvCollectiveContribution<'r>, BfvCollectiveError> {
        if !ptr::eq(self.setup, round1.setup) {
            return Err(BfvCollectiveError::Binding);
        }
        let context = self.setup.context;
        let len = self.setup.native.key_poly_len();
        let n = self.setup.native.n;
        let moduli = self.setup.native.key_moduli();
        let secret = self.setup.native.secret(self.setup.context, self.share)?;
        DcrtPolynomial(self.ephemeral.as_mut_slice()).sub_assign(
            &DcrtPolynomial(secret.as_slice()),
            n,
            moduli,
        );
        let mut values = vec![0; self.setup.masks.len()];
        for (pair, body) in round1
            .residues
            .chunks_exact(2 * len)
            .zip(values.chunks_exact_mut(len))
        {
            self.setup.native.noise_to(context, body, rng);
            let mut body = DcrtPolynomial(body);
            body.add_mul_assign(
                &DcrtPolynomial(secret.as_slice()),
                &DcrtPolynomial(&pair[..len]),
                n,
                moduli,
            );
            body.add_mul_assign(
                &DcrtPolynomial(self.ephemeral.as_slice()),
                &DcrtPolynomial(&pair[len..]),
                n,
                moduli,
            );
        }
        Ok(BfvCollectiveContribution {
            binding: &round1.binding,
            residues: values,
        })
    }
}

#[cfg(test)]
mod tests;
