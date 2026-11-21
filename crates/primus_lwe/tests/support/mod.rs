use primus_integer::FheUint;
use primus_lwe::{LweEncryptionParameters, LwePublicKey, LweSecretKey};
use primus_reduce::RingContext;
use rand::rngs::StdRng;

pub(super) fn public_key<T: FheUint, M: RingContext<T>>(
    secret: &LweSecretKey<T>,
    params: &LweEncryptionParameters<T, M>,
    rng: &mut StdRng,
) -> LwePublicKey<T> {
    LwePublicKey::generate(
        secret.as_view(),
        params.dimension(),
        params.cipher_modulus(),
        params.cipher_modulus_uniform_distr(),
        params.noise_distribution(),
        rng,
    )
}
