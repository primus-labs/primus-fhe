use algebra::{
    reduce::{AddReduceAssign, DotProductReduce, MulReduceAssign},
    AsInto, NTTField, Polynomial,
};
use rand::{
    distributions::{Distribution, Uniform},
    CryptoRng, Rng,
};

use crate::{LWECiphertext, LWEPlaintext, NTRUModulusSwitch, Parameters, SecretKeyPack};

/// The Key Switching Key.
pub struct KeySwitchingKey {
    /// LWE vector dimension, refers to **`n`** in the paper.
    lwe_dimension: usize,
    a: Vec<Vec<LWEPlaintext>>,
    b: Vec<LWEPlaintext>,
}

impl KeySwitchingKey {
    /// Performs key switching operation.
    pub fn key_switch(&self, ciphertext: NTRUModulusSwitch) -> LWECiphertext {
        let mut a: Vec<LWEPlaintext> = vec![0; self.lwe_dimension];
        let mut b: LWEPlaintext = 0;

        let mut data = ciphertext.data();
        let mut decompose_data: Vec<LWEPlaintext> = vec![0; data.len()];
        // data.de

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
        let basis: LWEPlaintext = 1 << key_switching_basis.bits();
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
                b_i.add_reduce_assign(e_i, lwe_modulus);
            });

        let f = modulus_switch(secret_key_pack.ring_secret_key(), parameters);
        let mut base: LWEPlaintext = 1;
        b.chunks_exact_mut(decompose_len).for_each(|b_i| {
            b_i.iter_mut()
                .zip(f.iter())
                .for_each(|(b_i_j, f_j)| b_i_j.add_reduce_assign(*f_j, lwe_modulus));
            base.mul_reduce_assign(basis, lwe_modulus)
        });

        Self {
            lwe_dimension,
            a,
            b,
        }
    }
}

fn modulus_switch<F: NTTField>(
    ntru_key: &Polynomial<F>,
    params: &Parameters<F>,
) -> Vec<LWEPlaintext> {
    let lwe_modulus_f64 = params.lwe_modulus_f64();
    let ntru_modulus_f64 = params.ntru_modulus_f64();

    let switch =
        |v: F| (v.get().as_into() * lwe_modulus_f64 / ntru_modulus_f64).round() as LWEPlaintext;
    let first = ntru_key[0];

    std::iter::once(first)
        .chain(ntru_key[1..].iter().rev().map(|v| -*v))
        .map(switch)
        .collect()
}
