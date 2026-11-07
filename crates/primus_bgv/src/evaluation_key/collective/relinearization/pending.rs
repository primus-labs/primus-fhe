//! Owner-local two-round response with erasing key-domain buffers.
use primus_glwe_rns::DcrtGlweSecretKey;
use primus_poly::DcrtPolynomial;
use zeroize::Zeroizing;

use super::{
    BgvCollectiveContribution, BgvCollectiveError, BgvCollectiveRelinearization,
    BgvCollectiveRoundOne, Round,
};

/// Private, non-cloneable state for exactly one owner's second-round response.
/// The actual source share is copied into erasing Q/QP setup storage; consuming
/// or dropping the state erases both that storage and u.
pub struct BgvCollectiveRelinearizationState<'p, 'c> {
    plan: &'p BgvCollectiveRelinearization<'c>,
    secret: Zeroizing<Vec<u64>>,
    ephemeral: Zeroizing<Vec<u64>>,
}

impl<'c> BgvCollectiveRelinearization<'c> {
    /// Samples private CBD1 u_i and produces the two-round key-domain response.
    /// Radix uses g*s_i/E errors in Q before final p scaling; Hybrid uses
    /// P*projector_j*s_i/pE errors directly in QP.
    /// # Errors
    /// Rejects an incompatible native share before sampling. Returned private state
    /// is single-use; caller additionally enforces its roster/setup policy.
    pub fn start<'p>(
        &'p self,
        share: &'p DcrtGlweSecretKey<u64>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<
        (
            BgvCollectiveContribution<'p>,
            BgvCollectiveRelinearizationState<'p, 'c>,
        ),
        BgvCollectiveError,
    > {
        self.plan.binding.secret(share)?;
        let context = self.plan.binding.context;
        let n = context.parameters().poly_length().get();
        let key = &self.plan.template;
        let len = key.key_poly_len();
        let base = key.key_base();
        let secret = key.secret(context, share)?;
        let mut ephemeral = Zeroizing::new(vec![0; len]);
        let minus_one: Vec<_> = base.moduli_values().iter().map(|&q| q - 1).collect();
        primus_distr::sample_crt_sparse_ternary_values_to(&mut ephemeral, n, &minus_one, rng);
        key.basis.transform_to_ntt(context, &mut ephemeral);
        let mut values = vec![0; self.round_one_binding.words];
        for (digit, (column, mask)) in values
            .chunks_exact_mut(2 * len)
            .zip(self.plan.masks.chunks_exact(len))
            .enumerate()
        {
            let (h0, h1) = column.split_at_mut(len);
            key.noise(context, h0, rng);
            key.noise(context, h1, rng);
            DcrtPolynomial(h0).add_mul_scalar_assign(
                &DcrtPolynomial(secret.as_slice()),
                key.weights(digit),
                n,
                base.moduli(),
            );
            DcrtPolynomial(&mut column[..len]).sub_mul_assign(
                &DcrtPolynomial(mask),
                &DcrtPolynomial(ephemeral.as_slice()),
                n,
                base.moduli(),
            );
            DcrtPolynomial(&mut column[len..]).add_mul_assign(
                &DcrtPolynomial(mask),
                &DcrtPolynomial(secret.as_slice()),
                n,
                base.moduli(),
            );
        }
        Ok((
            self.round_one_binding.try_import(values, Round::First)?,
            BgvCollectiveRelinearizationState {
                plan: self,
                secret,
                ephemeral,
            },
        ))
    }
}

impl BgvCollectiveRelinearizationState<'_, '_> {
    /// Consumes private u_i and its key-domain share, returning
    /// `s_i*H0+(u_i-s_i)*H1+e2` (p*e2 for Hybrid).
    /// # Errors
    /// Rejects a different first-round setup; the private state remains consumed
    /// on every return/unwind. The protocol authenticates the complete round.
    pub fn round2<'p>(
        mut self,
        frozen: &'p BgvCollectiveRoundOne<'_>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<BgvCollectiveContribution<'p>, BgvCollectiveError>
    where
        Self: 'p,
    {
        let plan = self.plan;
        plan.check_frozen(frozen)?;
        let context = plan.plan.binding.context;
        let key = &plan.plan.template;
        let len = key.key_poly_len();
        let n = context.parameters().poly_length().get();
        let base = key.key_base();
        DcrtPolynomial(self.ephemeral.as_mut_slice()).sub_assign(
            &DcrtPolynomial(self.secret.as_slice()),
            n,
            base.moduli(),
        );
        let mut values = vec![0; plan.plan.binding.words];
        for (body, first) in values
            .chunks_exact_mut(len)
            .zip(frozen.values.chunks_exact(2 * len))
        {
            key.noise(context, body, rng);
            let (h0, h1) = first.split_at(len);
            let mut body = DcrtPolynomial(body);
            body.add_mul_assign(
                &DcrtPolynomial(self.secret.as_slice()),
                &DcrtPolynomial(h0),
                n,
                base.moduli(),
            );
            body.add_mul_assign(
                &DcrtPolynomial(self.ephemeral.as_slice()),
                &DcrtPolynomial(h1),
                n,
                base.moduli(),
            );
        }
        plan.plan
            .binding
            .try_import(values, Round::Second(&frozen.values))
    }
}
