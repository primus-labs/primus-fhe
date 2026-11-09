use primus_glwe_rns::DcrtGlweSecretKey;
use primus_poly::DcrtPolynomial;

use crate::{BfvContext, keys::BfvPublicKey};

use super::{
    BfvCollectiveAggregate, BfvCollectiveContribution, BfvCollectiveError,
    contribution::{Binding, validate_payload},
    share::{distribution, owner, secret},
};

/// Common-mask collective level-zero BFV public-key setup.
/// Each party contributes `-A*s_i+e_i`; finalize inserts A exactly once.
pub struct BfvCollectivePublicKey<'a> {
    context: &'a BfvContext,
    mask: Vec<u64>,
    binding: Binding,
}
impl<'a> BfvCollectivePublicKey<'a> {
    /// Samples public uniform A after checking the exact first-version law.
    pub fn try_new<R: rand::Rng + rand::CryptoRng>(
        context: &'a BfvContext,
        rng: &mut R,
    ) -> Result<Self, BfvCollectiveError> {
        distribution(context)?;
        let mut mask = vec![0; context.rns_poly_len(0)];
        let sampling = context.parameters().encryption_parameters();
        primus_distr::sample_crt_uniform_values_to(
            &mut mask,
            context.parameters().poly_length().get(),
            sampling.cipher_moduli_uniform_distr(),
            rng,
        );
        Ok(Self {
            context,
            mask,
            binding: Binding::new(),
        })
    }
    /// Binds an authenticated, canonical public mask to this actual context.
    /// The protocol establishes uniformity and the intended common-mask identity.
    pub fn try_from_common_mask(
        context: &'a BfvContext,
        mask: Vec<u64>,
    ) -> Result<Self, BfvCollectiveError> {
        distribution(context)?;
        validate_payload(
            context.parameters().poly_length().get(),
            context.codec(0).moduli_values(),
            &mask,
            context.rns_poly_len(0),
        )?;
        Ok(Self {
            context,
            mask,
            binding: Binding::new(),
        })
    }
    /// Public common A payload; no private native key columns are exposed.
    #[must_use]
    pub fn common_mask(&self) -> &[u64] {
        &self.mask
    }
    /// Expected canonical transport residue count for one body contribution.
    #[must_use]
    pub fn contribution_len(&self) -> usize {
        self.mask.len()
    }
    /// Samples only this party's body contribution using its individual share.
    pub fn contribute<R: rand::Rng + rand::CryptoRng>(
        &self,
        share: &DcrtGlweSecretKey<u64>,
        rng: &mut R,
    ) -> Result<BfvCollectiveContribution<'_>, BfvCollectiveError> {
        owner(share, self.context)?;
        let context = self.context;
        let n = context.parameters().poly_length().get();
        let basis = context.codec(0).base_q();
        let mut body = vec![0; self.mask.len()];
        context
            .parameters()
            .encryption_parameters()
            .sample_noise_to(&mut body, basis.moduli_values(), rng);
        context.table().transform_slice(&mut body);
        DcrtPolynomial(body.as_mut_slice()).sub_mul_assign(
            &DcrtPolynomial(&self.mask),
            &DcrtPolynomial(secret(share, self.mask.len())),
            n,
            basis.moduli(),
        );
        // Native NTT and modular kernels produce canonical residues.
        Ok(BfvCollectiveContribution {
            binding: &self.binding,
            residues: body,
        })
    }
    /// Checks a transported body before rebinding it to this setup instance.
    pub fn try_import_contribution(
        &self,
        residues: Vec<u64>,
    ) -> Result<BfvCollectiveContribution<'_>, BfvCollectiveError> {
        validate_payload(
            self.context.parameters().poly_length().get(),
            self.context.codec(0).moduli_values(),
            &residues,
            self.mask.len(),
        )?;
        Ok(BfvCollectiveContribution {
            binding: &self.binding,
            residues,
        })
    }
    /// Allocates a public accumulator for a fixed nonempty authenticated roster.
    pub fn aggregate(
        &self,
        expected: usize,
    ) -> Result<BfvCollectiveAggregate<'_>, BfvCollectiveError> {
        BfvCollectiveAggregate::new(
            &self.binding,
            self.context.parameters().poly_length().get(),
            self.context.codec(0).base_q().moduli(),
            self.mask.len(),
            expected,
        )
    }
    /// Consumes a complete body sum and constructs the ordinary public key.
    pub fn finalize(
        &self,
        aggregate: BfvCollectiveAggregate<'_>,
    ) -> Result<BfvPublicKey, BfvCollectiveError> {
        let mut body = aggregate.finish(&self.binding)?;
        body.extend_from_slice(&self.mask);
        Ok(BfvPublicKey::from_collective(self.context, body))
    }
}
