use std::slice::ChunksExact;

use algebra::{FieldDiscreteGaussianSampler, NTTField, NTTPolynomial, Polynomial};
use lattice::{DecompositionSpace, NTTGadgetRLWE, PolynomialSpace, LWE, NTTRLWE, RLWE};
use rand::{CryptoRng, Rng};

use crate::{BlindRotationType, LWEModulusType, LWEMsgType, NTRUCiphertext, SecretKeyPack};

/// The Key Switching Key.
///
/// This struct stores the key
/// that switch a ciphertext of the ring Secret Key
/// to a [`LWE<F>`] ciphertext of the LWE Secret Key.
#[derive(Debug, Clone, Default)]
pub struct KeySwitchingKey<F: NTTField> {
    /// LWE vector dimension, refers to **`n`** in the paper.
    lwe_dimension: usize,
    /// Key Switching Key data
    key: Vec<NTTGadgetRLWE<F>>,
}

impl<F: NTTField> KeySwitchingKey<F> {
    /// Generates a new [`KeySwitchingKey`].
    pub fn generate<R, M, C>(
        secret_key_pack: &SecretKeyPack<M, C, F>,
        chi: FieldDiscreteGaussianSampler,
        mut rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
        M: LWEMsgType,
        C: LWEModulusType,
    {
        let parameters = secret_key_pack.parameters();
        let lwe_dimension = parameters.lwe_dimension();
        let key_switching_basis = parameters.key_switching_basis();

        let extended_lwe_dimension = lwe_dimension.next_power_of_two();
        let ring_dimension = parameters.ring_dimension();

        assert!(extended_lwe_dimension <= ring_dimension);

        // negative convertion
        let convert = |v: &C| {
            if *v == C::ZERO {
                F::zero()
            } else if *v == C::ONE {
                F::neg_one()
            } else {
                F::one()
            }
        };

        // s = [s_0, 0,..., 0, -s_{n-1},..., -s_1]
        let mut s = <Polynomial<F>>::new(
            secret_key_pack
                .lwe_secret_key()
                .iter()
                .map(convert)
                .collect(),
        );
        s.resize(extended_lwe_dimension, F::zero());
        s[0] = -s[0];
        s[1..].reverse();

        let lwe_sk = s.into_ntt_polynomial();

        let len = key_switching_basis.decompose_len();
        let basis = F::new(key_switching_basis.basis());
        let blind_rotation_type = parameters.blind_rotation_type();

        let key = if extended_lwe_dimension == ring_dimension {
            let mut ring_sk = match blind_rotation_type {
                BlindRotationType::RLWE => -secret_key_pack.ntt_ring_secret_key(),
                BlindRotationType::NTRU => secret_key_pack.ntt_ring_secret_key().clone(),
            };

            let k = (0..len)
                .map(|i| {
                    let mut sample =
                        <NTTRLWE<F>>::generate_random_zero_sample(&lwe_sk, chi, &mut rng);

                    *sample.b_mut() += &ring_sk;

                    if i < len - 1 {
                        ring_sk.mul_scalar_assign(basis);
                    }

                    sample
                })
                .collect();
            vec![NTTGadgetRLWE::new(k, key_switching_basis)]
        } else {
            let (mut key, mut store): (Vec<Polynomial<F>>, F) = match blind_rotation_type {
                BlindRotationType::RLWE => (
                    secret_key_pack
                        .ring_secret_key()
                        .as_slice()
                        .rchunks_exact(extended_lwe_dimension)
                        .map(|part| -Polynomial::from_slice(part))
                        .collect(),
                    -secret_key_pack.ring_secret_key()[0],
                ),
                BlindRotationType::NTRU => (
                    secret_key_pack
                        .ring_secret_key()
                        .as_slice()
                        .rchunks_exact(extended_lwe_dimension)
                        .map(|part| Polynomial::from_slice(part))
                        .collect(),
                    secret_key_pack.ring_secret_key()[0],
                ),
            };

            for k_i in &mut key {
                let temp = -k_i[0];
                k_i[0] = store;
                store = temp;
            }

            key.into_iter()
                .map(|z| {
                    let mut ntt_z = z.into_ntt_polynomial();
                    let k = (0..len)
                        .map(|i| {
                            let mut sample =
                                <NTTRLWE<F>>::generate_random_zero_sample(&lwe_sk, chi, &mut rng);

                            *sample.b_mut() += &ntt_z;

                            if i < len - 1 {
                                ntt_z.mul_scalar_assign(basis);
                            }

                            sample
                        })
                        .collect();
                    NTTGadgetRLWE::new(k, key_switching_basis)
                })
                .collect()
        };

        Self { lwe_dimension, key }
    }

    /// Performs key switching operation.
    pub fn key_switch_for_rlwe(&self, ciphertext: &RLWE<F>) -> LWE<F> {
        let extended_lwe_dimension = self.lwe_dimension.next_power_of_two();

        let init = <NTTRLWE<F>>::new(
            NTTPolynomial::zero(extended_lwe_dimension),
            NTTPolynomial::new(vec![ciphertext.b()[0]; extended_lwe_dimension]),
        );

        let iter = ciphertext.a_slice().chunks_exact(extended_lwe_dimension);

        self.key_switch_inner(extended_lwe_dimension, init, iter)
    }

    /// Performs key switching operation.
    pub fn key_switch_for_ntru(&self, ciphertext: &NTRUCiphertext<F>) -> LWE<F> {
        let extended_lwe_dimension = self.lwe_dimension.next_power_of_two();

        // Because the lwe ciphertext extracted from a ntru ciphertext always has `b = 0`.
        let init = <NTTRLWE<F>>::zero(extended_lwe_dimension);

        let iter = ciphertext.as_slice().chunks_exact(extended_lwe_dimension);

        self.key_switch_inner(extended_lwe_dimension, init, iter)
    }

    fn key_switch_inner(
        &self,
        extended_lwe_dimension: usize,
        mut init: NTTRLWE<F>,
        iter: ChunksExact<F>,
    ) -> LWE<F> {
        let mut polynomial_space = PolynomialSpace::new(extended_lwe_dimension);
        let mut decompose_space = DecompositionSpace::new(extended_lwe_dimension);

        self.key.iter().zip(iter).for_each(|(k_i, a_i)| {
            polynomial_space.copy_from(a_i);
            init.add_assign_gadget_rlwe_mul_polynomial_inplace_fast(
                k_i,
                &mut polynomial_space,
                &mut decompose_space,
            );
        });

        <RLWE<F>>::from(init).extract_partial_lwe_reverse_locally(self.lwe_dimension)
    }
}
