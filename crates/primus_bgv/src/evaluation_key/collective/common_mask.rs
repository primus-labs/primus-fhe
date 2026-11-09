//! Public-key bodies and centered inputs use the same native common-mask arithmetic.
use primus_data::Data;
use primus_glwe_rns::DcrtGlweSecretKey;
use primus_poly::{DcrtPolynomial, Polynomial};

use crate::{BgvCiphertext, BgvClient, BgvContext, keys::BgvPublicKey};

use super::{
    messages::{
        BgvCollectiveAggregate, BgvCollectiveContribution, BgvCollectiveError, Binding, Round,
    },
    secret_prefix,
};

struct CommonMask<'c> {
    binding: Binding<'c>,
    mask: Vec<u64>,
}

impl<'c> CommonMask<'c> {
    fn sample(
        context: &'c BgvContext,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<Self, BgvCollectiveError> {
        let binding = Binding::top(context)?;
        let parameters = context.parameters();
        let mut mask = vec![0; binding.words];
        primus_distr::sample_crt_uniform_values_to(
            &mut mask,
            parameters.poly_length().get(),
            parameters
                .encryption_parameters()
                .cipher_moduli_uniform_distr(),
            rng,
        );
        Ok(Self { binding, mask })
    }

    fn from_mask(context: &'c BgvContext, mask: Vec<u64>) -> Result<Self, BgvCollectiveError> {
        let binding = Binding::top(context)?;
        binding.validate(&mask)?;
        Ok(Self { binding, mask })
    }

    fn encrypt_body(
        &self,
        share: &DcrtGlweSecretKey<u64>,
        rng: &mut impl rand::CryptoRng,
        add_plaintext: impl FnOnce(&mut [u64]),
    ) -> Vec<u64> {
        let context = self.binding.context;
        let parameters = context.parameters();
        let mut body = vec![0; self.binding.words];
        crate::client::sample_scaled_noise(context, 0, &mut body, rng);
        add_plaintext(&mut body);
        context.table().transform_slice(&mut body);
        DcrtPolynomial(body.as_mut_slice()).sub_mul_assign(
            &DcrtPolynomial(self.mask.as_slice()),
            &DcrtPolynomial(secret_prefix(share, self.binding.words)),
            parameters.poly_length().get(),
            parameters.base_q().moduli(),
        );
        body
    }

    fn finish(
        &self,
        aggregate: BgvCollectiveAggregate<'_>,
    ) -> Result<Vec<u64>, BgvCollectiveError> {
        let (mut values, _) = self.binding.finish(aggregate, Round::Body)?;
        values.extend_from_slice(&self.mask);
        Ok(values)
    }
}

/// Common-mask public-key setup with native phase `p*sum(e_i)`.
/// The mask is inserted once, while only bodies are added.
pub struct BgvCollectivePublicKey<'c> {
    common: CommonMask<'c>,
}

impl<'c> BgvCollectivePublicKey<'c> {
    /// Samples public uniform NTT mask A using caller-owned randomness.
    /// # Errors
    /// Rejects a context outside the exact CBD1/CBD21 family before sampling.
    pub fn try_new(
        context: &'c BgvContext,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<Self, BgvCollectiveError> {
        Ok(Self {
            common: CommonMask::sample(context, rng)?,
        })
    }

    /// Imports the public mask after exact length/canonical-residue checks.
    /// # Correctness
    /// Authenticated setup binds this exact context/NTT convention and a uniform A.
    /// # Errors
    /// Rejects the sampling family, shape or noncanonical residues.
    pub fn try_from_common_mask(
        context: &'c BgvContext,
        mask: Vec<u64>,
    ) -> Result<Self, BgvCollectiveError> {
        Ok(Self {
            common: CommonMask::from_mask(context, mask)?,
        })
    }

    /// Borrows the public NTT mask, without exposing evaluation-key storage.
    #[must_use]
    pub fn common_mask(&self) -> &[u64] {
        &self.common.mask
    }

    /// Produces `-A*s_i+p*e_i` from one owner's share.
    /// # Errors
    /// Rejects incompatible geometry, ordered Q or declared support before sampling.
    /// Actual share sampling and NTT provenance remain caller contracts.
    pub fn contribute<'p>(
        &'p self,
        share: &DcrtGlweSecretKey<u64>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<BgvCollectiveContribution<'p>, BgvCollectiveError> {
        self.common.binding.secret(share)?;
        let body = self.common.encrypt_body(share, rng, |_| {});
        Ok(self.common.binding.contribution(body, Round::Body))
    }

    /// Imports a public body after protocol identity/metadata validation.
    /// # Errors
    /// Rejects wrong complete length or noncanonical residues.
    pub fn try_import(
        &self,
        body: Vec<u64>,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.common.binding.try_import(body, Round::Body)
    }

    /// Allocates one empty public body sum.
    #[must_use]
    pub fn aggregate(&self) -> BgvCollectiveAggregate<'_> {
        self.common.binding.aggregate(Round::Body)
    }

    /// Consumes a nonempty, protocol-complete body sum into an existing native key.
    /// # Errors
    /// Rejects an aborted, empty or differently bound sum. Roster completeness is caller-owned.
    pub fn finalize(
        &self,
        aggregate: BgvCollectiveAggregate<'_>,
    ) -> Result<BgvPublicKey, BgvCollectiveError> {
        let values = self.common.finish(aggregate)?;
        Ok(BgvPublicKey::from_collective(
            self.common.binding.context,
            BgvCiphertext::from_raw(values),
        ))
    }
}

/// One centered additive-input domain with an independent public common A.
/// The caller consumes its per-party input authorization before `contribute`.
pub struct BgvSeededInput<'c> {
    common: CommonMask<'c>,
}

impl<'c> BgvSeededInput<'c> {
    /// Samples a fresh uniform public NTT mask from caller-owned random words.
    ///
    /// The prepared integer distributions use unbiased rejection sampling.
    /// Public mask values may be published; this does not publish the random
    /// generator's internal seed/state or authorize reuse as a public-key mask.
    /// # Errors
    /// Rejects an unsupported sampling family before allocating or sampling.
    pub fn try_new(
        context: &'c BgvContext,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<Self, BgvCollectiveError> {
        Ok(Self {
            common: CommonMask::sample(context, rng)?,
        })
    }

    /// Imports the public uniform common mask in this exact NTT convention.
    /// # Correctness
    /// Authenticated setup must establish a fresh, independent uniform A. A
    /// public short seed and deterministic expansion do not establish that
    /// statistical distribution; neither does a canonical-storage check.
    /// # Errors
    /// Rejects wrong family, full length or canonical range.
    pub fn try_from_common_mask(
        context: &'c BgvContext,
        common_mask: Vec<u64>,
    ) -> Result<Self, BgvCollectiveError> {
        Ok(Self {
            common: CommonMask::from_mask(context, common_mask)?,
        })
    }

    /// Borrows the domain's public NTT mask.
    #[must_use]
    pub fn common_mask(&self) -> &[u64] {
        &self.common.mask
    }

    /// Borrows the actual numerical context that owns this input's NTT tables.
    #[must_use]
    pub const fn context(&self) -> &'c BgvContext {
        self.common.binding.context
    }

    /// Produces `B_i=-A*s_i+center(m_i)+p*e_i` from this owner's share.
    /// # Errors
    /// Rejects other contexts or invalid plaintext before sampling/writes.
    pub fn contribute<'p, A: Data<Elem = u64>>(
        &'p self,
        client: &BgvClient<'_>,
        input: &Polynomial<A>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<BgvCollectiveContribution<'p>, BgvCollectiveError> {
        self.common.binding.client(client)?;
        let context = self.common.binding.context;
        let parameters = context.parameters();
        if input.as_ref().len() != parameters.poly_length().get()
            || input
                .as_ref()
                .iter()
                .any(|&x| x >= parameters.plain_modulus().value())
        {
            return Err(BgvCollectiveError::Plaintext);
        }
        let body = self.common.encrypt_body(client.secret_key(), rng, |body| {
            crate::client::add_plaintext(context, input.as_ref(), body, true);
        });
        self.common.binding.try_import(body, Round::Body)
    }

    /// Imports a body only after its authenticated domain/party check.
    /// # Errors
    /// Rejects incomplete or noncanonical payloads.
    pub fn try_import(
        &self,
        body: Vec<u64>,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.common.binding.try_import(body, Round::Body)
    }

    /// Allocates an empty sum containing no common mask yet.
    #[must_use]
    pub fn aggregate(&self) -> BgvCollectiveAggregate<'_> {
        self.common.binding.aggregate(Round::Body)
    }

    /// Inserts A once and consumes the nonempty body aggregate.
    /// The freshly encoded sum has plaintext correction factor one.
    /// # Errors
    /// Rejects an aborted, empty or differently bound sum. Caller checks complete roster.
    pub fn finalize(
        &self,
        aggregate: BgvCollectiveAggregate<'_>,
    ) -> Result<BgvCiphertext<Vec<u64>>, BgvCollectiveError> {
        let values = self.common.finish(aggregate)?;
        Ok(BgvCiphertext::from_bound(
            values,
            self.common.binding.context,
            0,
        ))
    }
}
