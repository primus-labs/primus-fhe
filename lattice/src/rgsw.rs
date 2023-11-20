use algebra::{
    field::NTTField,
    polynomial::{NTTPolynomial, Poly},
};

use crate::{GadgetRLWE, RLWE};

/// Represents a ciphertext in the Ring-GSW (Ring Learning With Errors) homomorphic encryption scheme.
///
/// The `RGSW` struct holds two components, `c_m` and `c_neg_s_m`, each of type [`GadgetRLWE`]. These components are
/// integral to the RGSW encryption scheme, which is a variant of GSW encryption that operates over polynomial
/// rings for efficiency. This scheme is often used in lattice-based cryptography for constructing fully
/// homomorphic encryption systems.
///
/// The [`GadgetRLWE`] structures `c_m` and `c_neg_s_m` contain encrypted data that, when used together, allow for the
/// encrypted computation of linear and non-linear operations on ciphertexts without decrypting them.
/// These gadget representations play a crucial role in performing homomorphic operations by controlling noise
/// growth and enabling efficient arithmetic on encrypted data.
///
/// The struct is generic over a type `F` that must implement the `NTTField` trait, indicating that field
/// operations are compatible with Number Theoretic Transforms. This is essential for the efficient polynomial
/// arithmetic required by the encryption scheme.
///
/// # Fields
/// * `c_neg_s_m: GadgetRLWE<F>` - The first part of the RGSW ciphertext, which is often used for homomorphic operations
///   and can represent the encrypted data multiplied by some secret value.
/// * `c_m: GadgetRLWE<F>` - The second part of the RGSW ciphertext, typically representing the encrypted data.
#[derive(Debug, Clone)]
pub struct RGSW<F: NTTField> {
    c_neg_s_m: GadgetRLWE<F>,
    c_m: GadgetRLWE<F>,
}

impl<F: NTTField> RGSW<F> {
    /// Creates a new [`RGSW<F>`].
    #[inline]
    pub fn new(c_neg_s_m: GadgetRLWE<F>, c_m: GadgetRLWE<F>) -> Self {
        Self { c_neg_s_m, c_m }
    }

    /// Returns a reference to the `c_neg_s_m` of this [`RGSW<F>`].
    #[inline]
    pub fn c_neg_s_m(&self) -> &GadgetRLWE<F> {
        &self.c_neg_s_m
    }

    /// Returns a reference to the `c_m` of this [`RGSW<F>`].
    #[inline]
    pub fn c_m(&self) -> &GadgetRLWE<F> {
        &self.c_m
    }

    /// Returns a reference to the basis of this [`RGSW<F>`].
    #[inline]
    pub fn basis(&self) -> F::Base {
        self.c_neg_s_m.basis()
    }

    /// Performs a multiplication on the `self` [`RGSW<F>`] with another `rlwe` [`RLWE<F>`],
    /// return a [`RLWE<F>`].
    ///
    /// # Attention
    /// The message of **`self`** is restricted to small messages `m`, typically `m = ±X^v`
    #[inline]
    pub fn mul_with_rlwe(&self, rlwe: &RLWE<F>) -> RLWE<F> {
        self.c_neg_s_m()
            .mul_with_polynomial(rlwe.a())
            .add_element_wise(&self.c_m().mul_with_polynomial(rlwe.b()))
    }

    /// Performs a multiplication on the `self` [`RGSW<F>`] with another `rgsw` [`RGSW<F>`],
    /// return a [`RGSW<F>`].
    ///
    /// # Attention
    /// The message of **`rhs`** is restricted to small messages `m`, typically `m = ±X^v`
    #[inline]
    pub fn mul_with_rgsw(&self, rhs: &RGSW<F>) -> RGSW<F> {
        let basis = self.basis();

        let ntt_c_neg_s_m = rhs.c_neg_s_m().to_ntt_poly();
        let ntt_c_m = rhs.c_m().to_ntt_poly();

        let c0_data: Vec<RLWE<F>> = self
            .c_neg_s_m()
            .iter()
            .map(|rlwe| ntt_rgsw_mul_rlwe(&ntt_c_neg_s_m, &ntt_c_m, rlwe, basis))
            .collect();
        let c_neg_s_m = GadgetRLWE::new(c0_data, basis);

        let c1_data: Vec<RLWE<F>> = self
            .c_m()
            .iter()
            .map(|rlwe| ntt_rgsw_mul_rlwe(&ntt_c_neg_s_m, &ntt_c_m, rlwe, basis))
            .collect();
        let c_m = GadgetRLWE::new(c1_data, basis);

        RGSW::new(c_neg_s_m, c_m)
    }
}

/// An optimized version `rgsw * rlwe`, the rgsw input is its ntt polynomials.
///
/// This method can decrease the numbers of conversion of Number Theoretic Transforms.
fn ntt_rgsw_mul_rlwe<F: NTTField>(
    ntt_c_neg_s_m: &[(NTTPolynomial<F>, NTTPolynomial<F>)],
    ntt_c_m: &[(NTTPolynomial<F>, NTTPolynomial<F>)],
    rlwe: &RLWE<F>,
    basis: F::Base,
) -> RLWE<F> {
    let decomposed = rlwe.a().decompose(basis);
    let coeff_count = decomposed[0].coeff_count();
    let init = (
        NTTPolynomial::zero_with_coeff_count(coeff_count),
        NTTPolynomial::zero_with_coeff_count(coeff_count),
    );

    // a * (-s * m)
    let intermediate = ntt_c_neg_s_m
        .iter()
        .zip(decomposed)
        .fold(init, |acc, (r, p)| {
            let p = <NTTPolynomial<F>>::from(p);
            (acc.0 + &r.0 * &p, acc.1 + &r.1 * p)
        });

    // a * (-s * m) + b * m = (b - as) * m
    let decompose = rlwe.b().decompose(basis);
    ntt_c_m
        .iter()
        .zip(decompose)
        .fold(intermediate, |acc, (r, p)| {
            let p = <NTTPolynomial<F>>::from(p);
            (acc.0 + &r.0 * &p, acc.1 + &r.1 * p)
        })
        .into()
}

#[cfg(test)]
mod tests {
    use algebra::field::{BarrettConfig, FieldDistribution, Fp32};
    use algebra::polynomial::Polynomial;
    use rand::distributions::Standard;
    use rand::prelude::*;

    use super::*;

    #[test]
    fn test_rgsw_mul_rlwe() {
        // fn min_to_zero(value: Fp32) -> u32 {
        //     value.inner().min(P - value.inner())
        // }

        #[inline]
        fn decode(c: Fp32) -> u32 {
            (c.inner() as f64 * T as f64 / P as f64).round() as u32 % T
        }

        const P: u32 = Fp32::BARRETT_MODULUS.value();
        const N: usize = 1 << 3;
        const BASE: u32 = 1 << 2;
        const T: u32 = 128;

        let rng = &mut rand::thread_rng();
        let ternary = Fp32::ternary_distribution();
        let chi = Fp32::normal_distribution(0., 3.2).unwrap();

        let m0 = Polynomial::new(rng.sample_iter(Standard).take(N).collect());
        let m1 = Polynomial::new(rng.sample_iter(ternary).take(N).collect());

        let m0m1 = &m0 * &m1;

        let s = Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());

        let decompose_len = Fp32::decompose_len(BASE);

        let rgsw = {
            let m1_base_power = (0..decompose_len)
                .map(|i| {
                    let a =
                        Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
                    let e = Polynomial::new(rng.sample_iter(chi).take(N).collect::<Vec<Fp32>>());
                    let b = &a * &s + m1.mul_scalar(BASE.pow(i as u32)) + e;

                    RLWE::new(a, b)
                })
                .collect::<Vec<RLWE<Fp32>>>();

            let neg_sm1_base_power = (0..decompose_len)
                .map(|i| {
                    let a =
                        Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
                    let e = Polynomial::new(rng.sample_iter(chi).take(N).collect::<Vec<Fp32>>());
                    let b = &a * &s + e;

                    RLWE::new(a + m1.mul_scalar(BASE.pow(i as u32)), b)
                })
                .collect::<Vec<RLWE<Fp32>>>();

            RGSW::new(
                GadgetRLWE::new(neg_sm1_base_power, BASE),
                GadgetRLWE::new(m1_base_power, BASE),
            )
        };

        let (rlwe, _e) = {
            let a = Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
            let e = Polynomial::new(rng.sample_iter(chi).take(N).collect::<Vec<Fp32>>());
            let b = &a * &s + m0 + &e;

            (RLWE::new(a, b), e)
        };

        let rlwe_mul = rgsw.mul_with_rlwe(&rlwe);
        let decrypt_mul = rlwe_mul.b() - rlwe_mul.a() * &s;

        // let diff: Vec<u32> = (&m0m1 + e * m1 - &decrypt_mul)
        //     .into_iter()
        //     .map(min_to_zero)
        //     .collect();
        // println!("{:?}", diff);

        // let diff: Vec<u32> = (&m0m1 - &decrypt_mul)
        //     .into_iter()
        //     .map(min_to_zero)
        //     .collect();
        // println!("{:?}", diff);

        let decoded_m0m1: Vec<u32> = m0m1.into_iter().map(decode).collect();
        let decoded_decrypt: Vec<u32> = decrypt_mul.into_iter().map(decode).collect();
        assert_eq!(decoded_m0m1, decoded_decrypt);
    }

    #[test]
    fn test_rgsw_mul_rgsw() {
        #[inline]
        fn decode(c: Fp32) -> u32 {
            (c.inner() as f64 * T as f64 / P as f64).round() as u32 % T
        }

        const P: u32 = Fp32::BARRETT_MODULUS.value();
        const N: usize = 1 << 3;
        const BASE: u32 = 1 << 2;
        const T: u32 = 16;

        let rng = &mut rand::thread_rng();
        let ternary = Fp32::ternary_distribution();
        let chi = Fp32::normal_distribution(0., 3.2).unwrap();

        let m0 = Polynomial::new(rng.sample_iter(Standard).take(N).collect());
        let m1 = Polynomial::new(rng.sample_iter(ternary).take(N).collect());

        let m0m1 = &m0 * &m1;

        let s = Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());

        let decompose_len = Fp32::decompose_len(BASE);

        let rgsw_m1 = {
            let m1_base_power = (0..decompose_len)
                .map(|i| {
                    let a =
                        Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
                    let e = Polynomial::new(rng.sample_iter(chi).take(N).collect::<Vec<Fp32>>());
                    let b = &a * &s + m1.mul_scalar(BASE.pow(i as u32)) + e;

                    RLWE::new(a, b)
                })
                .collect::<Vec<RLWE<Fp32>>>();

            let neg_sm1_base_power = (0..decompose_len)
                .map(|i| {
                    let a =
                        Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
                    let e = Polynomial::new(rng.sample_iter(chi).take(N).collect::<Vec<Fp32>>());
                    let b = &a * &s + e;

                    RLWE::new(a + m1.mul_scalar(BASE.pow(i as u32)), b)
                })
                .collect::<Vec<RLWE<Fp32>>>();

            RGSW::new(
                GadgetRLWE::new(neg_sm1_base_power, BASE),
                GadgetRLWE::new(m1_base_power, BASE),
            )
        };

        let rgsw_m0 = {
            let m0_base_power = (0..decompose_len)
                .map(|i| {
                    let a =
                        Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
                    let e = Polynomial::new(rng.sample_iter(chi).take(N).collect::<Vec<Fp32>>());
                    let b = &a * &s + m0.mul_scalar(BASE.pow(i as u32)) + e;

                    RLWE::new(a, b)
                })
                .collect::<Vec<RLWE<Fp32>>>();

            let neg_sm0_base_power = (0..decompose_len)
                .map(|i| {
                    let a =
                        Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
                    let e = Polynomial::new(rng.sample_iter(chi).take(N).collect::<Vec<Fp32>>());
                    let b = &a * &s + e;

                    RLWE::new(a + m0.mul_scalar(BASE.pow(i as u32)), b)
                })
                .collect::<Vec<RLWE<Fp32>>>();

            RGSW::new(
                GadgetRLWE::new(neg_sm0_base_power, BASE),
                GadgetRLWE::new(m0_base_power, BASE),
            )
        };

        let rgsw_m0m1 = rgsw_m0.mul_with_rgsw(&rgsw_m1);

        let rlwe_m0m1 = &rgsw_m0m1.c_m().data()[0];
        let decrypted_m0m1 = rlwe_m0m1.b() - rlwe_m0m1.a() * &s;

        let decoded_m0m1: Vec<u32> = m0m1.iter().copied().map(decode).collect();
        let decoded_decrypt: Vec<u32> = decrypted_m0m1.into_iter().map(decode).collect();
        assert_eq!(decoded_m0m1, decoded_decrypt);

        let rlwe_neg_sm0m1 = &rgsw_m0m1.c_neg_s_m().data()[0];
        let decrypted_neg_sm0m1 = rlwe_neg_sm0m1.b() - rlwe_neg_sm0m1.a() * &s;
        let neg_sm0m1 = m0m1 * &s.mul_scalar(P - 1);

        let decoded_neg_sm0m1: Vec<u32> = neg_sm0m1.iter().copied().map(decode).collect();
        let decoded_decrypt_neg_sm0m1: Vec<u32> =
            decrypted_neg_sm0m1.into_iter().map(decode).collect();
        assert_eq!(decoded_neg_sm0m1, decoded_decrypt_neg_sm0m1);
    }
}
