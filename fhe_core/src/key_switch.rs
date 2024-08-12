use std::slice::ChunksExact;

use algebra::{Basis, FieldDiscreteGaussianSampler, NTTField, NTTPolynomial, Polynomial};
use lattice::{DecompositionSpace, NTTGadgetRLWE, PolynomialSpace, LWE, NTTRLWE, RLWE};
use rand::{CryptoRng, Rng};

use crate::{LWEModulusType, NTRUCiphertext, SecretKeyPack};

#[derive(Debug, Clone, Copy)]
enum Operation {
    AddAMulS,
    SubAMulS,
}

/// A enum type for different key switching purposes.
#[derive(Debug, Clone)]
pub enum EitherKeySwitchingKey<Q: NTTField, Qks: NTTField> {
    /// Modulus Switch, Key Switch and Modulus Switch
    MsKsMs(KeySwitchingKey<Qks>),
    /// Key Switch and Modulus Switch
    KsMs(KeySwitchingKey<Q>),
    /// Modulus Switch
    Ms,
}

impl<Q: NTTField, Qks: NTTField> EitherKeySwitchingKey<Q, Qks> {
    /// Returns `true` if the either key switching key is [`MsKsMs`].
    ///
    /// [`MsKsMs`]: EitherKeySwitchingKey::MsKsMs
    #[must_use]
    pub fn is_ms_ks_ms(&self) -> bool {
        matches!(self, Self::MsKsMs(..))
    }

    /// .
    pub fn as_ms_ks_ms(&self) -> Option<&KeySwitchingKey<Qks>> {
        if let Self::MsKsMs(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// Returns `true` if the either key switching key is [`KsMs`].
    ///
    /// [`KsMs`]: EitherKeySwitchingKey::KsMs
    #[must_use]
    pub fn is_ks_ms(&self) -> bool {
        matches!(self, Self::KsMs(..))
    }

    /// .
    pub fn as_ks_ms(&self) -> Option<&KeySwitchingKey<Q>> {
        if let Self::KsMs(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// Returns `true` if the either key switching key is [`Ms`].
    ///
    /// [`Ms`]: EitherKeySwitchingKey::Ms
    #[must_use]
    pub fn is_ms(&self) -> bool {
        matches!(self, Self::Ms)
    }
}

enum RingSK<'s, F: NTTField> {
    Owned(Polynomial<F>),
    Ref(&'s Polynomial<F>),
}

/// The Key Switching Key.
///
/// This struct stores the key
/// that switch a ciphertext of the ring Secret Key
/// to a [`LWE<F>`] ciphertext of the LWE Secret Key.
#[derive(Debug, Clone, Default)]
pub struct KeySwitchingKey<F: NTTField> {
    /// LWE vector dimension, refers to **n** in the paper.
    lwe_dimension: usize,
    /// Key Switching Key data
    key: Vec<NTTGadgetRLWE<F>>,
}

impl<F: NTTField> KeySwitchingKey<F> {
    fn generate_inner<R, C>(
        lwe_sk: &[C],
        ring_sk: RingSK<'_, F>,
        ntt_ring_sk: Option<&NTTPolynomial<F>>,
        key_switching_basis: Basis<F>,
        chi: FieldDiscreteGaussianSampler,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
        C: LWEModulusType,
    {
        let lwe_dimension = lwe_sk.len();
        let extended_lwe_dimension = lwe_dimension.next_power_of_two();
        let ring_dimension = match ring_sk {
            RingSK::Owned(ref sk) => sk.coeff_count(),
            RingSK::Ref(sk) => sk.coeff_count(),
        };

        // convertion
        let convert = |v: &C| {
            if *v == C::ZERO {
                F::zero()
            } else if *v == C::ONE {
                F::one()
            } else {
                F::neg_one()
            }
        };

        // s = [s_0, s_1,..., s_{n-1}, 0,..., 0]
        let mut s = <Polynomial<F>>::new(lwe_sk.iter().map(convert).collect());
        s.resize(extended_lwe_dimension, F::zero());

        let lwe_sk = s.into_ntt_polynomial();

        let len = key_switching_basis.decompose_len();
        let basis = F::new(key_switching_basis.basis());

        let key = if extended_lwe_dimension == ring_dimension {
            let mut sk = match ntt_ring_sk {
                Some(sk) => sk.clone(),
                None => match ring_sk {
                    RingSK::Owned(sk) => sk.into_ntt_polynomial(),
                    RingSK::Ref(sk) => sk.clone().into_ntt_polynomial(),
                },
            };

            let k = (0..len)
                .map(|i| {
                    let mut sample = <NTTRLWE<F>>::generate_random_zero_sample(&lwe_sk, chi, rng);

                    *sample.b_mut() += &sk;

                    if i < len - 1 {
                        sk.mul_scalar_assign(basis);
                    }

                    sample
                })
                .collect();
            vec![NTTGadgetRLWE::new(k, key_switching_basis)]
        } else {
            let key_chunks: Vec<Polynomial<F>> = match ring_sk {
                RingSK::Owned(ref sk) => sk.as_slice(),
                RingSK::Ref(sk) => sk.as_slice(),
            }
            .chunks_exact(extended_lwe_dimension)
            .map(|part| Polynomial::from_slice(part))
            .collect();

            key_chunks
                .into_iter()
                .map(|z| {
                    let mut ntt_z = z.into_ntt_polynomial();
                    let k = (0..len)
                        .map(|i| {
                            let mut sample =
                                <NTTRLWE<F>>::generate_random_zero_sample(&lwe_sk, chi, rng);

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

    /// Generates a new [`KeySwitchingKey`].
    pub fn generate_for_q<R, C, Qks>(
        secret_key_pack: &SecretKeyPack<C, F, Qks>,
        chi: FieldDiscreteGaussianSampler,
        rng: R,
    ) -> KeySwitchingKey<F>
    where
        R: Rng + CryptoRng,
        C: LWEModulusType,
        Qks: NTTField,
    {
        let parameters = secret_key_pack.parameters();

        let lwe_dimension = parameters.lwe_dimension();
        let extended_lwe_dimension = lwe_dimension.next_power_of_two();
        let ring_dimension = parameters.ring_dimension();
        assert!(extended_lwe_dimension <= ring_dimension);

        let key_switching_basis = parameters.key_switching_basis_q();

        Self::generate_inner(
            secret_key_pack.lwe_secret_key(),
            RingSK::Ref(secret_key_pack.ring_secret_key()),
            Some(secret_key_pack.ntt_ring_secret_key()),
            key_switching_basis,
            chi,
            rng,
        )
    }

    /// Generates a new [`KeySwitchingKey`].
    pub fn generate_for_qks<R, C, Q>(
        secret_key_pack: &SecretKeyPack<C, Q, F>,
        chi: FieldDiscreteGaussianSampler,
        rng: R,
    ) -> KeySwitchingKey<F>
    where
        R: Rng + CryptoRng,
        C: LWEModulusType,
        Q: NTTField,
    {
        let parameters = secret_key_pack.parameters();

        let lwe_dimension = parameters.lwe_dimension();
        let extended_lwe_dimension = lwe_dimension.next_power_of_two();
        let ring_dimension = parameters.ring_dimension();
        assert!(extended_lwe_dimension <= ring_dimension);

        let key_switching_basis = parameters.key_switching_basis_qks();

        let ring_secret_key = secret_key_pack.ring_secret_key();

        // convertion
        let convert = |v: &Q| {
            if v.is_zero() {
                F::zero()
            } else if v.is_one() {
                F::one()
            } else {
                F::neg_one()
            }
        };

        let ring_secret_key = <Polynomial<F>>::new(ring_secret_key.iter().map(convert).collect());

        Self::generate_inner(
            secret_key_pack.lwe_secret_key(),
            RingSK::Owned(ring_secret_key),
            None,
            key_switching_basis,
            chi,
            rng,
        )
    }

    /// Performs key switching operation.
    pub fn key_switch_for_rlwe(&self, mut ciphertext: RLWE<F>) -> LWE<F> {
        let extended_lwe_dimension = self.lwe_dimension.next_power_of_two();

        let init = <NTTRLWE<F>>::new(
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
    pub fn key_switch_for_ntru(&self, mut ciphertext: NTRUCiphertext<F>) -> LWE<F> {
        let extended_lwe_dimension = self.lwe_dimension.next_power_of_two();

        // Because the lwe ciphertext extracted from a ntru ciphertext always has `b = 0`.
        let init = <NTTRLWE<F>>::zero(extended_lwe_dimension);

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
    pub fn key_switch_for_lwe(&self, mut ciphertext: LWE<F>) -> LWE<F> {
        let extended_lwe_dimension = self.lwe_dimension.next_power_of_two();

        let init = <NTTRLWE<F>>::new(
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
        mut init: NTTRLWE<F>,
        iter: ChunksExact<F>,
        op: Operation,
    ) -> LWE<F> {
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

        <RLWE<F>>::from(init).extract_partial_lwe_locally(self.lwe_dimension)
    }
}
