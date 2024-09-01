use algebra::{modulus::PowOf2Modulus, NTTField};
use lattice::{decompose_lsb_bits_inplace, Basis, LWE};

use crate::{LWEModulusType, SecretKeyPack};

/// The Key Switching Key.
///
/// This struct stores the key
/// that switch a ciphertext of the ring Secret Key
/// to a [`LWE<C>`] ciphertext of the LWE Secret Key.
#[derive(Debug, Clone)]
pub struct KeySwitchingLWEKey<C: LWEModulusType> {
    /// LWE vector dimension, refers to **n** in the paper.
    lwe_dimension: usize,
    modulus: PowOf2Modulus<C>,
    basis: Basis<C>,
    /// Key Switching Key data
    ///
    /// k_{i, j, v}
    ///
    /// i \in \{0, dks-1\}
    /// j \in \{0, N-1\}
    /// v \in \{1, bks-1\}
    key: Vec<Vec<Vec<LWE<C>>>>,
}

impl<C: LWEModulusType> KeySwitchingLWEKey<C> {
    /// Generates a new [`KeySwitchingLWEKey`].
    pub fn generate<Q>(secret_key_pack: &SecretKeyPack<C, Q>) -> KeySwitchingLWEKey<C>
    where
        Q: NTTField,
    {
        let params = secret_key_pack.parameters();

        let lwe_dimension = params.lwe_dimension();
        let lwe_cipher_modulus_value = params.lwe_cipher_modulus_value();
        let lwe_cipher_modulus = params.lwe_cipher_modulus();
        let noise_distribution = params.key_switching_noise_distribution_for_lwe();

        let mut csrng = secret_key_pack.csrng_mut();

        let key_switching_basis =
            lattice::Basis::<C>::new(params.key_switching_basis_bits(), lwe_cipher_modulus_value);

        let neg_one = lwe_cipher_modulus_value - C::ONE;
        // conversion
        let convert = |v: &Q| {
            if v.is_zero() {
                C::ZERO
            } else if v.is_one() {
                C::ONE
            } else {
                neg_one
            }
        };

        let mut ring_sk: Vec<C> = secret_key_pack
            .ring_secret_key()
            .iter()
            .map(convert)
            .collect();

        let len = key_switching_basis.decompose_len();
        let basis = key_switching_basis.basis();
        let basis_usize: usize = basis.try_into().ok().unwrap();

        let sk = secret_key_pack.lwe_secret_key();

        let key: Vec<Vec<Vec<LWE<C>>>> = (0..len)
            .map(|j| {
                let inner: Vec<Vec<LWE<C>>> = ring_sk
                    .iter()
                    .map(|&z| {
                        let mut res = Vec::with_capacity(basis_usize - 2);
                        let mut v = C::ONE;
                        while v < basis {
                            let mut cipher = LWE::generate_random_zero_sample(
                                sk,
                                lwe_cipher_modulus_value,
                                lwe_cipher_modulus,
                                noise_distribution,
                                &mut *csrng,
                            );

                            cipher.b_mut().add_reduce_assign(
                                v.mul_reduce(z, lwe_cipher_modulus),
                                lwe_cipher_modulus,
                            );

                            res.push(cipher);
                            v = v + C::ONE;
                        }
                        res
                    })
                    .collect();

                if j < len - 1 {
                    ring_sk
                        .iter_mut()
                        .for_each(|v| v.mul_reduce_assign(basis, lwe_cipher_modulus))
                }

                inner
            })
            .collect();

        Self {
            lwe_dimension,
            modulus: lwe_cipher_modulus,
            basis: key_switching_basis,
            key,
        }
    }

    /// Performs key switching operation.
    pub fn key_switch_for_lwe(&self, mut ciphertext: LWE<C>) -> LWE<C> {
        let b = ciphertext.b();
        let a = ciphertext.a_mut();

        let mut result = LWE::new(vec![C::ZERO; self.lwe_dimension], C::ZERO);

        let mut decomposed = vec![C::ZERO; a.len()];
        self.key.iter().for_each(|inner| {
            decompose_lsb_bits_inplace(a, self.basis, &mut decomposed);
            decomposed.iter().zip(inner).for_each(|(&d_i, s_i)| {
                if !d_i.is_zero() {
                    let index: usize = d_i.try_into().ok().unwrap() - 1;
                    result.add_reduce_inplace_component_wise(&s_i[index], self.modulus);
                }
            });
        });

        result.neg_reduce_assign(self.modulus);
        result.b_mut().add_reduce_assign(b, self.modulus);
        result
    }
}
