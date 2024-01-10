use algebra::{NTTField, NTTPolynomial, Polynomial, Random, RandomNTTField, Ring};
use lattice::{NTTGadgetRLWE, LWE, NTTRLWE, RLWE};

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

        let mut init = RLWE::new(
            Polynomial::zero_with_coeff_count(self.lwe_dimension),
            Polynomial::zero_with_coeff_count(self.lwe_dimension),
        );
        init.b_mut()[0] = ciphertext.b();

        let mut init = <NTTRLWE<F>>::from(init);

        let rlwe_dimension = init.a().coeff_count();
        let basis = self.key[0].basis();
        let decompose_len = basis.decompose_len();

        let mut decompose = Vec::new();
        decompose.resize_with(decompose_len, || {
            <Polynomial<F>>::zero_with_coeff_count(rlwe_dimension)
        });

        self.key.iter().zip(a).for_each(|(k_i, a_i)| {
            init.sub_gadget_rlwe_mul_polynomial_inplace(k_i, a_i, &mut decompose);
        });

        <RLWE<F>>::from(init).extract_lwe()
    }
}

impl<F: RandomNTTField> KeySwitchingKey<F> {
    /// Generates a new [`KeySwitchingKey`].
    pub fn generate<R: Ring, Rng>(
        secret_key_pack: &SecretKeyPack<R, F>,
        chi: <F as Random>::NormalDistribution,
        mut rng: Rng,
    ) -> Self
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let parameters = secret_key_pack.parameters();
        let lwe_dimension = parameters.lwe_dimension();
        let key_switching_basis = parameters.key_switching_basis();
        let key_switching_basis_powers = parameters.key_switching_basis_powers();

        let s = <Polynomial<F>>::new(
            secret_key_pack
                .lwe_secret_key()
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

        let key = secret_key_pack
            .rlwe_secret_key()
            .as_slice()
            .chunks_exact(lwe_dimension)
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

        Self { lwe_dimension, key }
    }
}
