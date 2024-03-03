use algebra::{
    ntt_add_mul_assign_ref, NTTField, NTTPolynomial, Polynomial, Random, RandomNTTField,
};
use lattice::{DecompositionSpace, NTTGadgetRLWE, LWE, NTTRLWE, RLWE};

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
                <Polynomial<F>>::new(
                    std::iter::once(a[0])
                        .chain(a.iter().skip(1).rev().map(|&x| -x))
                        .collect(),
                )
            })
            .collect();

        let mut init = <NTTRLWE<F>>::new(
            NTTPolynomial::zero_with_coeff_count(self.lwe_dimension),
            NTTPolynomial::new(vec![ciphertext.b(); self.lwe_dimension]),
        );

        let mut decompose_space = DecompositionSpace::new(self.lwe_dimension);

        self.key.iter().zip(a).for_each(|(k_i, a_i)| {
            init.sub_assign_gadget_rlwe_mul_polynomial_inplace_fast(k_i, a_i, &mut decompose_space);
        });

        <RLWE<F>>::from(init).extract_lwe()
    }
}

impl<F: RandomNTTField> KeySwitchingKey<F> {
    /// Generates a new [`KeySwitchingKey`].
    pub fn generate<Rng>(
        secret_key_pack: &SecretKeyPack<F>,
        chi: <F as Random>::NormalDistribution,
        mut rng: Rng,
    ) -> Self
    where
        Rng: rand::Rng + rand::CryptoRng,
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

        let ntt_lwe_sk = s.into_ntt_polynomial();

        let len = key_switching_basis.decompose_len();

        let key = secret_key_pack
            .rlwe_secret_key()
            .as_slice()
            .chunks_exact(lwe_dimension)
            .map(|z| {
                let mut ntt_z = Polynomial::from_slice(z).into_ntt_polynomial();
                let k_i = (0..len)
                    .map(|i| {
                        let a = <NTTPolynomial<F>>::random(lwe_dimension, &mut rng);
                        let mut e = <Polynomial<F>>::random_with_dis(lwe_dimension, &mut rng, chi)
                            .into_ntt_polynomial();

                        ntt_add_mul_assign_ref(e.as_mut_slice(), &a, &ntt_lwe_sk);
                        let b = e + &ntt_z;

                        if i < len - 1 {
                            ntt_z.mul_scalar_inplace(key_switching_basis.basis());
                        }

                        NTTRLWECiphertext::new(a, b)
                    })
                    .collect::<Vec<NTTRLWECiphertext<F>>>();
                NTTGadgetRLWE::new(k_i, key_switching_basis)
            })
            .collect();

        Self { lwe_dimension, key }
    }
}
