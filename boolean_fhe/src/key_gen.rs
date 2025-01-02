use algebra::{integer::UnsignedInteger, NttField};
use rand::{CryptoRng, Rng};

use crate::{BooleanFheParameters, SecretKeyPack};

/// Struct of key generation.
pub struct KeyGen;

impl KeyGen {
    /// Generate key pair
    #[inline]
    pub fn generate_secret_key<C, Q, R>(
        params: BooleanFheParameters<C, Q>,
        rng: &mut R,
    ) -> SecretKeyPack<C, Q>
    where
        C: UnsignedInteger,
        Q: NttField,
        R: Rng + CryptoRng,
    {
        SecretKeyPack::new(params, rng)
    }
}
