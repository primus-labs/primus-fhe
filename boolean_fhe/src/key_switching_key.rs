use algebra::{FieldDiscreteGaussianSampler, NTTField, NTTPolynomial, Polynomial};
use lattice::{DecompositionSpace, NTTGadgetRLWE, LWE, NTTRLWE, RLWE};
use rand::{CryptoRng, Rng};

use crate::{ciphertext::NTTRLWECiphertext, SecretKeyPack};

/// The Key Switching Key.
///
/// This struct stores the key
/// to switch a [`LWE`] ciphertext from the RLWE Secret Key
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
        let a: Vec<Polynomial<F>> = ciphertext
            .a()
            .chunks_exact(self.lwe_dimension)
            .map(|a| {
                let mut p: Vec<F> = a.iter().map(|&x| -x).collect();
                p[0] = -p[0];
                p[1..].reverse();
                <Polynomial<F>>::new(p)
            })
            .collect();

        let mut init = <NTTRLWE<F>>::new(
            NTTPolynomial::zero(self.lwe_dimension),
            NTTPolynomial::new(vec![ciphertext.b(); self.lwe_dimension]),
        );

        let mut decompose_space = DecompositionSpace::new(self.lwe_dimension);

        self.key.iter().zip(a).for_each(|(k_i, a_i)| {
            init.sub_assign_gadget_rlwe_mul_polynomial_inplace_fast(k_i, a_i, &mut decompose_space);
        });

        <RLWE<F>>::from(init).extract_lwe()
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

        let s = <Polynomial<F>>::new(
            secret_key_pack
                .lwe_secret_key()
                .iter()
                .map(|&v| {
                    if v == 1 {
                        F::ONE
                    } else if v == 0 {
                        F::ZERO
                    } else {
                        F::NEG_ONE
                    }
                })
                .collect(),
        );

        let s = s.into_ntt_polynomial();

        let len = key_switching_basis.decompose_len();

        let key = secret_key_pack
            .rlwe_secret_key()
            .as_slice()
            .chunks_exact(lwe_dimension)
            .map(|z| {
                let mut ntt_z = Polynomial::from_slice(z).into_ntt_polynomial();
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
}
