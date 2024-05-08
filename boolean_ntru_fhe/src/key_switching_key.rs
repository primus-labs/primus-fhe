use algebra::{modulus::PowOf2Modulus, reduce::*, Field, NTTField};
use rand::{
    distributions::{Distribution, Uniform},
    CryptoRng, Rng,
};

use crate::{LWECiphertext, LWEPlaintext, SecretKeyPack};

/// The Key Switching Key.
pub struct KeySwitchingKey {
    /// LWE vector dimension, refers to **`n`** in the paper.
    lwe_dimension: usize,
    lwe_modulus: PowOf2Modulus<LWEPlaintext>,
    a: Vec<Vec<LWEPlaintext>>,
    b: Vec<LWEPlaintext>,
}

impl KeySwitchingKey {
    /// Performs key switching operation.
    pub fn key_switch(&self, decomposed_ciphertext: Vec<LWEPlaintext>) -> LWECiphertext {
        let mut a: Vec<LWEPlaintext> = vec![0; self.lwe_dimension];
        let mut b: LWEPlaintext = 0;

        for (&v, row) in decomposed_ciphertext.iter().zip(self.a.iter()) {
            if v == 1 {
                a.iter_mut()
                    .zip(row)
                    .for_each(|(x, &y)| x.add_reduce_assign(y, self.lwe_modulus));
            } else if v != 0 {
                a.iter_mut().zip(row).for_each(|(x, &y)| {
                    x.add_reduce_assign(y.mul_reduce(v, self.lwe_modulus), self.lwe_modulus)
                });
            }
        }

        for (&v, &b_i) in decomposed_ciphertext.iter().zip(self.b.iter()) {
            if v == 1 {
                b.add_reduce_assign(b_i, self.lwe_modulus);
            } else if v != 0 {
                b.add_reduce_assign(b_i.mul_reduce(v, self.lwe_modulus), self.lwe_modulus);
            }
        }

        LWECiphertext::new(a, b)
    }
}

impl KeySwitchingKey {
    /// Generates a new [`KeySwitchingKey`].
    pub fn generate<R, F: NTTField + Field<Value = LWEPlaintext>>(
        secret_key_pack: &SecretKeyPack<F>,
        mut rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let parameters = secret_key_pack.parameters();
        let lwe_modulus = parameters.lwe_modulus();
        let lwe_modulus_value = lwe_modulus.value();

        let dis = Uniform::new(0, lwe_modulus_value);

        let lwe_dimension = parameters.lwe_dimension();
        let ntru_dimension = parameters.ntru_dimension();
        let bits = parameters.key_switching_basis_bits();
        let b_ksk: LWEPlaintext = 1 << bits;
        let l_ksk = (LWEPlaintext::BITS - (lwe_modulus_value - 1).leading_zeros()).div_ceil(bits);

        let a = (0..ntru_dimension * l_ksk as usize)
            .map(|_| {
                dis.sample_iter(&mut rng)
                    .take(lwe_dimension)
                    .collect::<Vec<LWEPlaintext>>()
            })
            .collect::<Vec<_>>();

        let lwe_sk = secret_key_pack.lwe_secret_key();

        let mut b = a
            .iter()
            .map(|row_i| LWEPlaintext::dot_product_reduce(row_i, lwe_sk, lwe_modulus))
            .collect::<Vec<_>>();

        parameters
            .lwe_noise_distribution()
            .sample_iter(&mut rng)
            .zip(b.iter_mut())
            .for_each(|(e_i, b_i)| {
                b_i.add_reduce_assign(e_i, lwe_modulus);
            });

        let mut f: Vec<LWEPlaintext> = secret_key_pack
            .ring_secret_key()
            .iter()
            .map(|v| v.get().neg_reduce(lwe_modulus))
            .collect();
        f[1..].reverse();
        f[0].neg_reduce_assign(lwe_modulus);

        b.chunks_exact_mut(l_ksk as usize)
            .zip(f)
            .for_each(|(b_i, f_i)| {
                let mut coef_w_pwr = f_i;
                b_i.iter_mut().for_each(|b_i_j| {
                    b_i_j.add_reduce_assign(coef_w_pwr, lwe_modulus);
                    coef_w_pwr.mul_reduce_assign(b_ksk, lwe_modulus);
                });
            });

        Self {
            lwe_dimension,
            lwe_modulus,
            a,
            b,
        }
    }
}
