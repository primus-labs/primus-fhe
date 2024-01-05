use algebra::{Basis, NTTField, NTTPolynomial, Polynomial, Random, RandomNTTField, Ring};
use lattice::{NTTGadgetRLWE, LWE, RLWE};

use crate::{ciphertext::NTTRLWECiphertext, secret_key::RLWESecretKey};

/// Key Switching Key
pub struct KeySwitchingKey<F: NTTField> {
    key: Vec<NTTGadgetRLWE<F>>,
}

impl<F: NTTField> KeySwitchingKey<F> {
    pub(crate) fn key_switch(&self, ciphertext: LWE<F>, lwe_dimension: usize) -> LWE<F> {
        let a: Vec<Polynomial<F>> = ciphertext
            .a()
            .chunks_exact(lwe_dimension)
            .map(|a| {
                <Polynomial<F>>::new(
                    std::iter::once(a[0])
                        .chain(a.iter().skip(1).rev().map(|&x| -x))
                        .collect(),
                )
            })
            .collect();

        let mut init = RLWE::new(
            Polynomial::zero_with_coeff_count(lwe_dimension),
            Polynomial::zero_with_coeff_count(lwe_dimension),
        );
        init.b_mut()[0] = ciphertext.b();

        self.key
            .iter()
            .zip(a)
            .fold(init, |acc, (k_i, a_i)| {
                acc.sub_element_wise(&k_i.mul_with_polynomial(&a_i))
            })
            .extract_lwe()
    }
}

impl<F: RandomNTTField> KeySwitchingKey<F> {
    pub(crate) fn generate<R: Ring, Rng>(
        lwe_dimension: usize,
        lwe_secret_key: &[R],
        rlwe_secret_key: &RLWESecretKey<F>,
        key_switching_basis: Basis<F>,
        key_switching_basis_powers: &[F],
        chi: <F as Random>::NormalDistribution,
        mut rng: Rng,
    ) -> Self
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let s = <Polynomial<F>>::new(
            lwe_secret_key
                .iter()
                .map(|&v| {
                    if v.is_one() {
                        F::ONE
                    } else if v == R::NEG_ONE {
                        F::NEG_ONE
                    } else {
                        F::ZERO
                    }
                })
                .collect(),
        );

        let ntt_lwe_sk = s.to_ntt_polynomial();

        let key = rlwe_secret_key
            .as_slice()
            .chunks(lwe_dimension)
            .map(|z| {
                let ntt_z = Polynomial::from_slice(z).to_ntt_polynomial();
                let k_i = key_switching_basis_powers
                    .iter()
                    .map(|&key_switching_basis_power| {
                        let a = <NTTPolynomial<F>>::random(lwe_dimension, &mut rng);
                        let e = <Polynomial<F>>::random_with_dis(lwe_dimension, &mut rng, chi)
                            .to_ntt_polynomial();

                        let b = &a * &ntt_lwe_sk
                            + ntt_z.mul_scalar(key_switching_basis_power.inner())
                            + e;

                        NTTRLWECiphertext::new(a, b)
                    })
                    .collect::<Vec<NTTRLWECiphertext<F>>>();
                NTTGadgetRLWE::new(k_i, key_switching_basis)
            })
            .collect();

        Self { key }
    }
}
