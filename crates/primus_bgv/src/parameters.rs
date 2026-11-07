use crate::correction::gcd;
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{
    CrtGlweEncryptionParameters, CrtGlweEncryptionParametersError, SecretKeyDistr,
};
use primus_integer::BigUint;
use primus_lattice::{GlweDimension, GlweSize, GlweSizeError, RnsGlweSize};
use primus_modulus::BarrettModulus;
use primus_reduce::Reduce;
use primus_rns::{RNSBase, RnsError};
use primus_shape::PolyLength;

/// Invalid coefficient geometry, plaintext/ciphertext moduli or sampling law.
#[derive(Debug, thiserror::Error)]
pub enum BgvParametersError {
    /// A complete rank-one storage length cannot be represented.
    #[error(transparent)]
    Layout(#[from] GlweSizeError),
    /// The ciphertext moduli fail the RNS basis requirements.
    #[error(transparent)]
    RnsBase(#[from] RnsError),
    /// Secret/error sampling preparation failed.
    #[error(transparent)]
    Encryption(#[from] CrtGlweEncryptionParametersError<u64>),
    /// Plaintext modulus must be at least two and below every ciphertext prime.
    #[error("BGV plaintext modulus must satisfy 2 <= p < every q_i")]
    PlainModulus,
    /// A ciphertext modulus shares a factor with the plaintext modulus.
    #[error("BGV ciphertext modulus {modulus} at index {index} is not coprime to p")]
    PlaintextNotCoprime {
        /// Ordered basis index.
        index: usize,
        /// Rejected modulus.
        modulus: u64,
    },
    /// Even fresh private encryption could exceed the centered recovery interval.
    #[error("BGV fresh private error and plaintext exceed the Q/2 bound")]
    FreshRecovery,
}

/// Rank-one fixed-u64 BGV parameters with ciphertext moduli coprime to p.
///
/// Total Q may exceed 128 bits. One coefficient error is sampled and encoded
/// under all limbs, then multiplied by p; these are correlated residues of the
/// same signed integer, not independent per-limb errors. Plaintext p may be
/// composite for coefficient arithmetic and coprime to each q_i; ciphertext q_i must be prime for the
/// NTT workflow. Parameter preparation does not certify their primality.
pub struct BgvParameters {
    sampling: CrtGlweEncryptionParameters<u64>,
    base_q: RNSBase<u64, BarrettModulus<u64>>,
    plain_modulus: BarrettModulus<u64>,
    pub(crate) half_q: Vec<u64>,
    pub(crate) q_mod_p: u64,
}

impl BgvParameters {
    /// Prepares coefficient parameters with Gaussian or centered-binomial error sampling.
    ///
    /// # Errors
    /// Rejects invalid geometry, RNS/sampling parameters, noncoprime moduli
    /// or insufficient fresh private recovery margin. NTT compatibility is
    /// established by [`crate::BgvContext::try_new`].
    pub fn try_coefficients(
        poly_length: PolyLength,
        plain_modulus: BarrettModulus<u64>,
        cipher_moduli: &[BarrettModulus<u64>],
        secret_key_distr: SecretKeyDistr,
        error_distribution: ErrorDistribution,
    ) -> Result<Self, BgvParametersError> {
        let p = plain_modulus.value();
        if p < 2 || cipher_moduli.iter().any(|q| q.value() <= p) {
            return Err(BgvParametersError::PlainModulus);
        }
        for (index, q) in cipher_moduli.iter().enumerate() {
            if gcd(q.value(), p) != 1 {
                return Err(BgvParametersError::PlaintextNotCoprime {
                    index,
                    modulus: q.value(),
                });
            }
        }
        let base_q = RNSBase::new(cipher_moduli)?;
        let geometry = GlweSize::try_new(GlweDimension::new(1), poly_length)?;
        let size = RnsGlweSize::try_new(geometry, base_q.moduli_count())?;
        let sampling = CrtGlweEncryptionParameters::try_with_error_distribution(
            size,
            &base_q,
            secret_key_distr,
            error_distribution,
        )?;
        let mut half_q = base_q.moduli_product().0.to_vec();
        BigUint(&mut half_q[..]).right_shift_assign(1);
        let maximum = u128::from(p) * u128::from(sampling.noise_distribution().maximum_magnitude())
            + u128::from(p - 1);
        let bound = [maximum as u64, (maximum >> 64) as u64];
        if compare_words(&half_q, &bound).is_lt() {
            return Err(BgvParametersError::FreshRecovery);
        }
        let q_mod_p = plain_modulus.reduce(base_q.moduli_product().0);
        Ok(Self {
            sampling,
            base_q,
            plain_modulus,
            half_q,
            q_mod_p,
        })
    }

    /// Returns the full ciphertext/secret polynomial length N.
    #[must_use]
    pub fn poly_length(&self) -> PolyLength {
        self.size().poly_length()
    }
    /// Returns complete native rank-one geometry.
    #[must_use]
    pub fn size(&self) -> RnsGlweSize {
        self.sampling.size()
    }
    /// Returns the unique ordered Q basis.
    #[must_use]
    pub fn base_q(&self) -> &RNSBase<u64, BarrettModulus<u64>> {
        &self.base_q
    }
    /// Returns p, the coefficient plaintext modulus.
    #[must_use]
    pub fn plain_modulus(&self) -> BarrettModulus<u64> {
        self.plain_modulus
    }
    /// Returns the unique prepared secret/error/uniform sampling state.
    #[must_use]
    pub fn encryption_parameters(&self) -> &CrtGlweEncryptionParameters<u64> {
        &self.sampling
    }
}

pub(crate) fn compare_words(lhs: &[u64], rhs: &[u64]) -> std::cmp::Ordering {
    let lhs_length = lhs.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
    let rhs_length = rhs.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
    lhs_length.cmp(&rhs_length).then_with(|| {
        lhs[..lhs_length]
            .iter()
            .rev()
            .cmp(rhs[..rhs_length].iter().rev())
    })
}
