//! implementation of key generation.

use algebra::NTTField;
use fhe_core::{LWEModulusType, Parameters, SecretKeyPack};
use rand::{CryptoRng, Rng};

/// Struct of key generation.
pub struct KeyGen;

impl KeyGen {
    /// Generate key pair
    #[inline]
    pub fn generate_secret_key<C: LWEModulusType, Q: NTTField, R: Rng + CryptoRng>(
        params: Parameters<C, Q>,
        csrng: &mut R,
    ) -> SecretKeyPack<C, Q> {
        SecretKeyPack::new(params, csrng)
    }
}
