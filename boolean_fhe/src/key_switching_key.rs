use algebra::{FieldDiscreteGaussianSampler, NTTField, NTTPolynomial, Polynomial};
use lattice::{DecompositionSpace, NTTGadgetRLWE, PolynomialSpace, LWE, NTTRLWE, RLWE};
use rand::{CryptoRng, Rng};

use crate::{ciphertext::NTTRLWECiphertext, LWEPlaintext, SecretKeyPack};

/// The Key Switching Key.
///
/// This struct stores the key
/// that switch a [`LWE`] ciphertext of the RLWE Secret Key
/// to a [`LWE`] ciphertext of the LWE Secret Key.
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

        let modified_lwe_dimension = n.next_power_of_two();

        let mut init = <NTTRLWE<F>>::new(
            NTTPolynomial::zero(modified_lwe_dimension),
            NTTPolynomial::new(vec![ciphertext.b(); modified_lwe_dimension]),
        );

        let mut polynomial_space = PolynomialSpace::new(modified_lwe_dimension);
        let mut decompose_space = DecompositionSpace::new(modified_lwe_dimension);

        let a_iter = ciphertext.a().chunks_exact(modified_lwe_dimension);

        self.key.iter().zip(a_iter).for_each(|(k_i, a_i)| {
            polynomial_space.copy_from(a_i);
            init.add_assign_gadget_rlwe_mul_polynomial_inplace_fast(
                k_i,
                &mut polynomial_space,
                &mut decompose_space,
            );
        });

        <RLWE<F>>::from(init).extract_short_lwe_reverse_locally(n)
    }
}

impl<F: NTTField> KeySwitchingKey<F> {
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

        let modified_lwe_dimension = lwe_dimension.next_power_of_two();
        let rlwe_dimension = parameters.rlwe_dimension();

        assert!(rlwe_dimension.is_power_of_two());
        assert!(modified_lwe_dimension <= rlwe_dimension);

        // negative convertion
        let convert = |v: &LWEPlaintext| match *v {
            0 => F::ZERO,
            1 => F::NEG_ONE,
            _ => F::ONE,
        };

        // s = [s_0, 0,..., 0, -s_{n-1},..., -s_1]
        let mut s = <Polynomial<F>>::new(
            secret_key_pack
                .lwe_secret_key()
                .iter()
                .map(convert)
                .collect(),
        );
        s.resize(modified_lwe_dimension, F::ZERO);
        s[0] = -s[0];
        s[1..].reverse();

        let lwe_sk = s.into_ntt_polynomial();

        let len = key_switching_basis.decompose_len();
        let basis = F::new(key_switching_basis.basis());

        let key = if modified_lwe_dimension == rlwe_dimension {
            let mut rlwe_sk = -secret_key_pack.ntt_rlwe_secret_key();

            let k = (0..len)
                .map(|i| {
                    let mut sample =
                        <NTTRLWE<F>>::generate_random_zero_sample(&lwe_sk, chi, &mut rng);

                    *sample.b_mut() += &rlwe_sk;

                    if i < len - 1 {
                        rlwe_sk.mul_scalar_assign(basis);
                    }

                    sample
                })
                .collect::<Vec<NTTRLWECiphertext<F>>>();
            vec![NTTGadgetRLWE::new(k, key_switching_basis)]
        } else {
            let mut key: Vec<Polynomial<F>> = secret_key_pack
                .rlwe_secret_key()
                .as_slice()
                .rchunks_exact(modified_lwe_dimension)
                .map(|part| -Polynomial::from_slice(part))
                .collect();
            let mut store = -secret_key_pack.rlwe_secret_key()[0];
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
                        .collect::<Vec<NTTRLWECiphertext<F>>>();
                    NTTGadgetRLWE::new(k, key_switching_basis)
                })
                .collect()
        };

        Self { lwe_dimension, key }
    }
}
