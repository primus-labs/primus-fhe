//! Physical phase products for callers that supply their own opening policy.
use primus_data::{Data, DataMut};
use primus_poly::DcrtPolynomial;

use crate::{BgvCiphertext, BgvClient};

use super::super::error::validate_level;
use super::{
    messages::{BgvCollectiveError, validate_values},
    secret_prefix,
};

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
/// The protocol authenticates the plaintext correction factor with the complete
/// ciphertext and applies its inverse once to the aggregate centered phase
/// modulo p.
///
/// # Errors
/// Rejects an incompatible context/level, wrong complete lengths or
/// noncanonical input before writing to the output.
pub fn raw_unflooded_partial_phase_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
    client: &BgvClient<'_>,
    input: &BgvCiphertext<A>,
    level: usize,
    output: &mut DcrtPolynomial<B>,
) -> Result<(), BgvCollectiveError> {
    let context = client.context;
    validate_level(context, level)?;
    input
        .validate_binding(context, level)
        .map_err(|_| BgvCollectiveError::Binding)?;
    let n = context.parameters().poly_length().get();
    let base = context.base_q(level);
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
        &DcrtPolynomial(secret_prefix(client.secret_key(), len)),
        n,
        base.moduli(),
    );
    Ok(())
}
