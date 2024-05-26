use algebra::{FieldDiscreteGaussianSampler, NTTField, NTTPolynomial, Polynomial};
use lattice::{DecompositionSpace, NTTGadgetRLWE, PolynomialSpace, LWE, NTTRLWE, RLWE};
use rand::{CryptoRng, Rng};

use crate::{
    ciphertext::NTTRLWECiphertext, LWEModulusType, NTRUCiphertext, NTRUSecretKeyPack, SecretKeyPack,
};

/// The Key Switching Key.
///
/// This struct stores the key
/// that switch a [`LWE`] ciphertext of the RLWE Secret Key
/// to a [`LWE`] ciphertext of the LWE Secret Key.
#[derive(Debug, Clone)]
pub struct KeySwitchingKey<F: NTTField> {
    /// LWE vector dimension, refers to **`n`** in the paper.
    lwe_dimension: usize,
    /// Key Switching Key data
    key: Vec<NTTGadgetRLWE<F>>,
}

impl<F: NTTField> KeySwitchingKey<F> {
    /// Performs key switching operation.
    pub fn key_switch(&self, ciphertext: LWE<F>) -> LWE<F> {
        let n = self.lwe_dimension;

        let mut init = <NTTRLWE<F>>::new(
            NTTPolynomial::zero(n),
            NTTPolynomial::new(vec![ciphertext.b(); n]),
        );

        let mut polynomial_space = PolynomialSpace::new(n);
        let mut decompose_space = DecompositionSpace::new(n);

        let a_iter = ciphertext.a().chunks_exact(n);

        self.key.iter().zip(a_iter).for_each(|(k_i, a_i)| {
            polynomial_space.copy_from(a_i);
            init.add_assign_gadget_rlwe_mul_polynomial_inplace_fast(
                k_i,
                &mut polynomial_space,
                &mut decompose_space,
            );
        });

        <RLWE<F>>::from(init).extract_lwe_reverse_locally()
    }

    /// Generates a new [`KeySwitchingKey`].
    pub fn generate<R>(
        secret_key_pack: &SecretKeyPack<F>,
        chi: FieldDiscreteGaussianSampler,
        mut rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let parameters = secret_key_pack.parameters();
        let lwe_dimension = parameters.lwe_dimension();
        let key_switching_basis = parameters.key_switching_basis();

        // negative convertion
        let convert = |v: &LWEModulusType| match *v {
            0 => F::ZERO,
            1 => F::NEG_ONE,
            _ => F::ONE,
        };

        // s = [s_0, -s_{n-1},..., -s_1]
        let mut s = <Polynomial<F>>::new(
            secret_key_pack
                .lwe_secret_key()
                .iter()
                .map(convert)
                .collect(),
        );
        s[0] = -s[0];
        s[1..].reverse();

        let s = s.into_ntt_polynomial();

        let len = key_switching_basis.decompose_len();

        // z = [z_0, -z_{N-1},..., -z_1]
        let mut key = secret_key_pack.rlwe_secret_key().as_slice().to_vec();
        key[1..].reverse();
        key[1..].iter_mut().for_each(|v| *v = -*v);

        let key = key
            .chunks_exact(lwe_dimension)
            .map(|z| {
                let mut p = Polynomial::from_slice(z);
                p[0] = -p[0];
                p[1..].reverse();

                let mut ntt_z = p.into_ntt_polynomial();
                let k_i = (0..len)
                    .map(|i| {
                        let mut sample =
                            <NTTRLWE<F>>::generate_random_zero_sample(&s, chi, &mut rng);

                        *sample.b_mut() += &ntt_z;

                        if i < len - 1 {
                            ntt_z.mul_scalar_assign(F::new(key_switching_basis.basis()));
                        }

                        sample
                    })
                    .collect::<Vec<NTTRLWECiphertext<F>>>();
                NTTGadgetRLWE::new(k_i, key_switching_basis)
            })
            .collect();

        Self { lwe_dimension, key }
    }

    /// Performs key switching operation for ntru.
    pub fn key_switch_ntru(&self, ciphertext: &NTRUCiphertext<F>) -> LWE<F> {
        let n = self.lwe_dimension;

        // Because the lwe ciphertext extracted from a ntru ciphertext always has `b = 0`.
        let mut init = <NTTRLWE<F>>::zero(n);

        let mut polynomial_space = PolynomialSpace::new(n);
        let mut decompose_space = DecompositionSpace::new(n);

        let a_iter = ciphertext.as_slice().chunks_exact(n);

        self.key.iter().zip(a_iter).for_each(|(k_i, a_i)| {
            polynomial_space.copy_from(a_i);
            init.add_assign_gadget_rlwe_mul_polynomial_inplace_fast(
                k_i,
                &mut polynomial_space,
                &mut decompose_space,
            );
        });

        <RLWE<F>>::from(init).extract_lwe_reverse_locally()
    }

    /// Generates a new [`KeySwitchingKey`].
    pub fn generate_ntru<R>(
        secret_key_pack: &NTRUSecretKeyPack<F>,
        chi: FieldDiscreteGaussianSampler,
        mut rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let parameters = secret_key_pack.parameters();
        let lwe_dimension = parameters.lwe_dimension();
        let key_switching_basis = parameters.key_switching_basis();

        // negative convertion
        let convert = |v: &LWEModulusType| match *v {
            0 => F::ZERO,
            1 => F::NEG_ONE,
            _ => F::ONE,
        };

        // s = [s_0, -s_{n-1},..., -s_1]
        let mut s = <Polynomial<F>>::new(
            secret_key_pack
                .lwe_secret_key()
                .iter()
                .map(convert)
                .collect(),
        );
        s[0] = -s[0];
        s[1..].reverse();

        let s = s.into_ntt_polynomial();

        let len = key_switching_basis.decompose_len();

        // f = [-f_0, f_{N-1},..., f_1]
        let mut key = secret_key_pack.ring_secret_key().as_slice().to_vec();
        key[0] = -key[0];
        key[1..].reverse();

        let key = key
            .chunks_exact(lwe_dimension)
            .map(|z| {
                let mut p = Polynomial::from_slice(z);
                p[0] = -p[0];
                p[1..].reverse();

                let mut ntt_z = p.into_ntt_polynomial();
                let k_i: Vec<NTTRLWE<F>> = (0..len)
                    .map(|i| {
                        let mut sample =
                            <NTTRLWE<F>>::generate_random_zero_sample(&s, chi, &mut rng);

                        *sample.b_mut() += &ntt_z;

                        if i < len - 1 {
                            ntt_z.mul_scalar_assign(F::new(key_switching_basis.basis()));
                        }

                        sample
                    })
                    .collect();
                NTTGadgetRLWE::new(k_i, key_switching_basis)
            })
            .collect();

        Self { lwe_dimension, key }
    }
}
