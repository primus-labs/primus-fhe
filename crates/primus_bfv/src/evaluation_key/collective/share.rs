use primus_data::{Data, DataMut};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_poly::DcrtPolynomial;
use zeroize::Zeroizing;

use crate::{BfvCiphertext, BfvClient, BfvContext, evaluation_key::error::validate_level};

use super::{BfvCollectiveError, contribution::validate_payload};

pub(super) fn distribution(context: &BfvContext) -> Result<(), BfvCollectiveError> {
    let sampling = context.parameters().encryption_parameters();
    if sampling.secret_key_distr() != SecretKeyDistr::SparseTernary
        || sampling.noise_distribution().distribution()
            != (ErrorDistribution::CenteredBinomial { eta: 21 })
    {
        return Err(BfvCollectiveError::Distribution);
    }
    Ok(())
}
pub(super) fn owner(
    share: &DcrtGlweSecretKey<u64>,
    context: &BfvContext,
) -> Result<(), BfvCollectiveError> {
    share
        .validate_parameters(
            context.parameters().size(),
            context.parameters().base_q().moduli(),
        )
        .map_err(|_| BfvCollectiveError::Binding)?;
    if share.distr() != SecretKeyDistr::SparseTernary {
        return Err(BfvCollectiveError::Distribution);
    }
    Ok(())
}
pub(super) fn secret(share: &DcrtGlweSecretKey<u64>, len: usize) -> &[u64] {
    let DcrtPolynomial(values) = share.iter_dcrt_poly().next().expect("rank-one secret");
    &values[..len]
}
/// Writes this owner's native `c1*s_i` into local DCRT scratch without c0,
/// decoding, flooding or allocation.
///
/// # Security
/// Keep this raw product private. A chosen mask of `c1 = 1` exposes the secret
/// share. The protocol must authenticate and authorize the complete request
/// and add its prescribed privacy flooding before releasing a contribution.
///
/// # Correctness
/// The input must use the intended collective secret and actual NTT convention.
///
/// # Errors
/// Rejects an incompatible context/level, wrong complete lengths or
/// noncanonical input before writing to the output.
pub fn raw_unflooded_partial_phase_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
    client: &BfvClient<'_>,
    input: &BfvCiphertext<A>,
    level: usize,
    output: &mut DcrtPolynomial<B>,
) -> Result<(), BfvCollectiveError> {
    let context = client.context;
    input
        .validate_binding(context, level)
        .map_err(|_| BfvCollectiveError::Binding)?;
    validate_level(context, level)?;
    let n = context.parameters().poly_length().get();
    let codec = context.codec(level);
    let len = n * codec.moduli_count();
    validate_payload(n, codec.moduli_values(), input.as_ref(), 2 * len)?;
    if output.as_ref().len() != len {
        return Err(BfvCollectiveError::Payload);
    }
    output.as_mut().copy_from_slice(&input.as_ref()[len..]);
    output.mul_assign(
        &DcrtPolynomial(secret(client.secret_key(), len)),
        n,
        codec.base_q().moduli(),
    );
    Ok(())
}

impl BfvContext {
    /// Embeds an individual CBD1 N/2 secret as `s_i(X²)` in this N ring.
    ///
    /// The source key is borrowed without constructing a recovery client. The
    /// source/target contexts must use the intended actual NTT conventions.
    /// Geometry and declared secret support are checked before conversion; every
    /// coefficient limb must encode the same signed {-1,0,1} values. This checks
    /// support, not the private share's probability distribution. Temporary
    /// coefficient and embedded secrets are erased on return or unwind.
    pub fn try_embed_secret_from(
        &self,
        source: &BfvContext,
        share: &DcrtGlweSecretKey<u64>,
    ) -> Result<DcrtGlweSecretKey<u64>, BfvCollectiveError> {
        distribution(self)?;
        owner(share, source)?;
        let n = source.parameters().poly_length().get();
        if self.parameters().poly_length().get() != 2 * n
            || self.parameters().codec().t() != source.parameters().codec().t()
        {
            return Err(BfvCollectiveError::Embedding);
        }
        let mut coefficients = Zeroizing::new(secret(share, source.rns_poly_len(0)).to_vec());
        source.table().inverse_transform_slice(&mut coefficients);
        let mut embedded = Zeroizing::new(vec![0i64; 2 * n]);
        for (index, &value) in coefficients[..n].iter().enumerate() {
            embedded[2 * index] = if value == 0 {
                0
            } else if value == 1 {
                1
            } else if value == source.codec(0).moduli_values()[0] - 1 {
                -1
            } else {
                return Err(BfvCollectiveError::Embedding);
            };
        }
        for (limb, &q) in coefficients
            .chunks_exact(n)
            .zip(source.codec(0).moduli_values())
        {
            if limb.iter().enumerate().any(|(i, &x)| {
                x != match embedded[2 * i] {
                    -1 => q - 1,
                    0 => 0,
                    _ => 1,
                }
            }) {
                return Err(BfvCollectiveError::Embedding);
            }
        }
        let coefficient_key = GlweSecretKey::new(
            embedded.to_vec(),
            self.parameters().size().glwe_size(),
            SecretKeyDistr::SparseTernary,
        );
        Ok(DcrtGlweSecretKey::from_coeff_secret_key(
            &coefficient_key,
            self.table(),
        ))
    }
}
