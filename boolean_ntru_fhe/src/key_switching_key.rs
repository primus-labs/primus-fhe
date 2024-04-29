use algebra::reduce::DotProductReduce;
use algebra::NTTField;
use rand::{
    distributions::{Distribution, Uniform},
    CryptoRng, Rng,
};

use crate::{LWECiphertext, LWEPlaintext, NTRUModulusSwitch, SecretKeyPack};

/// The Key Switching Key.
///
/// This struct stores the key
/// to switch a [`LWE`] ciphertext from the RLWE Secret Key
/// to a [`LWE`] ciphertext of the LWE Secret Key.
pub struct KeySwitchingKey {
    /// LWE vector dimension, refers to **`n`** in the paper.
    lwe_dimension: usize,
    /// Key Switching Key data
    a: Vec<Vec<LWEPlaintext>>,
}

impl KeySwitchingKey {
    /// Performs key switching operation.
    pub fn key_switch(&self, ciphertext: NTRUModulusSwitch) -> LWECiphertext {
        todo!("Key Switching Operation")
    }
}

impl KeySwitchingKey {
    /// Generates a new [`KeySwitchingKey`].
    pub fn generate<R, F: NTTField>(secret_key_pack: &SecretKeyPack<F>, mut rng: R) -> Self
    where
        R: Rng + CryptoRng,
    {
        let parameters = secret_key_pack.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let dis = Uniform::new(0, lwe_modulus.value());

        let lwe_dimension = parameters.lwe_dimension();
        let ntru_dimension = parameters.ntru_dimension();
        let key_switching_basis = parameters.key_switching_basis();
        let decompose_len = key_switching_basis.decompose_len();

        let a = (0..ntru_dimension * decompose_len)
            .map(|_| {
                dis.sample_iter(&mut rng)
                    .take(lwe_dimension)
                    .collect::<Vec<LWEPlaintext>>()
            })
            .collect::<Vec<_>>();

        let mut b = a
            .iter()
            .map(|a_row_i| {
                LWEPlaintext::dot_product_reduce(
                    a_row_i,
                    secret_key_pack.lwe_secret_key(),
                    lwe_modulus,
                )
            })
            .collect::<Vec<_>>();

        parameters
            .lwe_noise_distribution()
            .sample_iter(&mut rng)
            .take(ntru_dimension * decompose_len)
            .zip(b.iter_mut())
            .for_each(|(e_i, b_i)| {
                *b_i += e_i;
            });

        // let mut it = b.chunks_exact_mut(decompose_len);
        // let first_part = it.next().unwrap();
        // let temp = 1;
        // let base =
        // for b_i in first_part {

        // }

        todo!("Generate Key Switching Key")
    }
}
