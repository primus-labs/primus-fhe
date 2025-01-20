use algebra::{integer::UnsignedInteger, reduce::RingReduce, NttField};
use rand::{CryptoRng, Rng};

use crate::{BooleanFheParameters, SecretKeyPack};

/// Struct of key generation.
pub struct KeyGen;

impl KeyGen {
    /// Generate key pair
    #[inline]
    pub fn generate_secret_key<C, LweModulus, Q, R>(
        params: BooleanFheParameters<C, LweModulus, Q>,
        rng: &mut R,
    ) -> SecretKeyPack<C, LweModulus, Q>
    where
        C: UnsignedInteger,
        LweModulus: RingReduce<C>,
        Q: NttField,
        R: Rng + CryptoRng,
    {
        SecretKeyPack::new(params, rng)
    }
}
