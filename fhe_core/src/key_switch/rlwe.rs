use std::slice::ChunksExact;

use algebra::{Basis, NTTField, NTTPolynomial, Polynomial};
use lattice::{DecompositionSpace, NTTGadgetRLWE, PolynomialSpace, LWE, NTTRLWE, RLWE};

use crate::{LWEModulusType, NTRUCiphertext, SecretKeyPack};

#[derive(Debug, Clone, Copy)]
enum Operation {
    AddAMulS,
    SubAMulS,
}

/// The Key Switching Key.
///
/// This struct stores the key
/// that switch a ciphertext of the ring Secret Key
/// to a [`LWE<F>`] ciphertext of the LWE Secret Key.
#[derive(Debug, Clone, Default)]
pub struct KeySwitchingRLWEKey<Q: NTTField> {
    /// LWE vector dimension, refers to **n** in the paper.
    lwe_dimension: usize,
    /// Key Switching Key data
    key: Vec<NTTGadgetRLWE<Q>>,
}

impl<Q: NTTField> KeySwitchingRLWEKey<Q> {
    /// Generates a new [`KeySwitchingKey`].
    pub fn generate<C>(secret_key_pack: &SecretKeyPack<C, Q>) -> KeySwitchingRLWEKey<Q>
    where
        C: LWEModulusType,
    {
        let parameters = secret_key_pack.parameters();

        let lwe_dimension = parameters.lwe_dimension();
        let extended_lwe_dimension = lwe_dimension.next_power_of_two();
        let ring_dimension = parameters.ring_dimension();
        assert!(extended_lwe_dimension <= ring_dimension);

        let chi = parameters.key_switching_noise_distribution_for_ring();
        let mut csrng = secret_key_pack.csrng_mut();

        let key_switching_basis = Basis::<Q>::new(parameters.key_switching_basis_bits());

        // convertion
        let convert = |v: &C| {
            if *v == C::ZERO {
                Q::zero()
            } else if *v == C::ONE {
                Q::one()
            } else {
                Q::neg_one()
            }
        };

        // s = [s_0, s_1,..., s_{n-1}, 0,..., 0]
        let mut s = <Polynomial<Q>>::new(
            secret_key_pack
                .lwe_secret_key()
                .iter()
                .map(convert)
                .collect(),
        );
        s.resize(extended_lwe_dimension, Q::zero());

        let lwe_sk = s.into_ntt_polynomial();

        let len = key_switching_basis.decompose_len();
        let basis = Q::new(key_switching_basis.basis());

        let key = if extended_lwe_dimension == ring_dimension {
            let mut sk = secret_key_pack.ntt_ring_secret_key().clone();

            let k = (0..len)
                .map(|i| {
                    let mut sample =
                        <NTTRLWE<Q>>::generate_random_zero_sample(&lwe_sk, chi, &mut *csrng);

                    *sample.b_mut() += &sk;

                    if i < len - 1 {
                        sk.mul_scalar_assign(basis);
                    }

                    sample
                })
                .collect();
            vec![NTTGadgetRLWE::new(k, key_switching_basis)]
        } else {
            let key_chunks: Vec<Polynomial<Q>> = secret_key_pack
                .ring_secret_key()
                .as_slice()
                .chunks_exact(extended_lwe_dimension)
                .map(|part| Polynomial::from_slice(part))
                .collect();

            key_chunks
                .into_iter()
                .map(|z| {
                    let mut ntt_z = z.into_ntt_polynomial();
                    let k = (0..len)
                        .map(|i| {
                            let mut sample = <NTTRLWE<Q>>::generate_random_zero_sample(
                                &lwe_sk,
                                chi,
                                &mut *csrng,
                            );

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
    pub fn key_switch_for_rlwe(&self, mut ciphertext: RLWE<Q>) -> LWE<Q> {
        let extended_lwe_dimension = self.lwe_dimension.next_power_of_two();

        let init = <NTTRLWE<Q>>::new(
            NTTPolynomial::zero(extended_lwe_dimension),
            NTTPolynomial::new(vec![ciphertext.b()[0]; extended_lwe_dimension]),
        );

        if ciphertext.a_slice().len() != extended_lwe_dimension {
            let a = ciphertext.a_mut_slice();
            a[0] = -a[0];
            a[1..].reverse();
            a.chunks_exact_mut(extended_lwe_dimension)
                .for_each(|chunk| {
                    chunk[0] = -chunk[0];
                    chunk[1..].reverse();
                });
        }

        let iter = ciphertext.a_slice().chunks_exact(extended_lwe_dimension);

        self.key_switch_inner(extended_lwe_dimension, init, iter, Operation::SubAMulS)
    }

    /// Performs key switching operation.
    pub fn key_switch_for_ntru(&self, mut ciphertext: NTRUCiphertext<Q>) -> LWE<Q> {
        let extended_lwe_dimension = self.lwe_dimension.next_power_of_two();

        // Because the lwe ciphertext extracted from a ntru ciphertext always has `b = 0`.
        let init = <NTTRLWE<Q>>::zero(extended_lwe_dimension);

        if ciphertext.as_slice().len() != extended_lwe_dimension {
            let a = ciphertext.as_mut_slice();
            a[0] = -a[0];
            a[1..].reverse();
            a.chunks_exact_mut(extended_lwe_dimension)
                .for_each(|chunk| {
                    chunk[0] = -chunk[0];
                    chunk[1..].reverse();
                });
        }

        let iter = ciphertext.as_slice().chunks_exact(extended_lwe_dimension);

        self.key_switch_inner(extended_lwe_dimension, init, iter, Operation::AddAMulS)
    }

    /// Performs key switching operation.
    pub fn key_switch_for_lwe(&self, mut ciphertext: LWE<Q>) -> LWE<Q> {
        let extended_lwe_dimension = self.lwe_dimension.next_power_of_two();

        let init = <NTTRLWE<Q>>::new(
            NTTPolynomial::zero(extended_lwe_dimension),
            NTTPolynomial::new(vec![ciphertext.b(); extended_lwe_dimension]),
        );

        if ciphertext.a().len() != extended_lwe_dimension {
            let a = ciphertext.a_mut();
            a.chunks_exact_mut(extended_lwe_dimension)
                .for_each(|chunk| {
                    chunk[1..].reverse();
                    chunk[1..].iter_mut().for_each(|v| *v = -*v);
                });
        } else {
            let a = ciphertext.a_mut();
            a[1..].reverse();
            a[1..].iter_mut().for_each(|v| *v = -*v);
        }

        let iter = ciphertext.a().chunks_exact(extended_lwe_dimension);

        self.key_switch_inner(extended_lwe_dimension, init, iter, Operation::SubAMulS)
    }

    fn key_switch_inner(
        &self,
        extended_lwe_dimension: usize,
        mut init: NTTRLWE<Q>,
        iter: ChunksExact<Q>,
        op: Operation,
    ) -> LWE<Q> {
        let mut polynomial_space = PolynomialSpace::new(extended_lwe_dimension);
        let mut decompose_space = DecompositionSpace::new(extended_lwe_dimension);

        match op {
            Operation::AddAMulS => {
                self.key.iter().zip(iter).for_each(|(k_i, a_i)| {
                    polynomial_space.copy_from(a_i);

                    init.add_assign_gadget_rlwe_mul_polynomial_inplace_fast(
                        k_i,
                        &mut polynomial_space,
                        &mut decompose_space,
                    );
                });
            }
            Operation::SubAMulS => {
                self.key.iter().zip(iter).for_each(|(k_i, a_i)| {
                    polynomial_space.copy_from(a_i);

                    init.sub_assign_gadget_rlwe_mul_polynomial_inplace_fast(
                        k_i,
                        &mut polynomial_space,
                        &mut decompose_space,
                    );
                });
            }
        }

        <RLWE<Q>>::from(init).extract_partial_lwe_locally(self.lwe_dimension)
    }
}
