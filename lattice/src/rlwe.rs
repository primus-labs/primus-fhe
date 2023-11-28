use algebra::field::NTTField;
use algebra::polynomial::{NTTPolynomial, Poly, Polynomial};

use crate::LWE;

/// A cryptographic structure for Ring Learning with Errors (RLWE).
/// This structure is used in advanced cryptographic systems and protocols, particularly
/// those that require efficient homomorphic encryption properties. It consists of two polynomials
/// `a` and `b` over a finite field that supports Number Theoretic Transforms (NTT), which is
/// often necessary for efficient polynomial multiplication.
///
/// The `RLWE` struct is generic over a type `F` which is bounded by the `NTTField` trait, ensuring
/// that the operations of addition, subtraction, and multiplication are performed in a field suitable
/// for NTT. This is crucial for the security and correctness of cryptographic operations based on RLWE.
///
/// The fields `a` and `b` are kept private within the crate to maintain encapsulation and are
/// accessible through public API functions that enforce any necessary invariants. They represent the
/// public key and error term respectively in the RLWE scheme.
///
/// # Fields
/// * `a`: [`Polynomial<F>`] - Represents the first component or the public key in the RLWE structure.
/// It is a polynomial where the coefficients are elements of the field `F`.
/// * `b`: [`Polynomial<F>`] - Represents the second component or the error term in the RLWE structure.
/// It's also a polynomial with coefficients in the field `F`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RLWE<F: NTTField> {
    pub(crate) a: Polynomial<F>,
    pub(crate) b: Polynomial<F>,
}

impl<F: NTTField> From<(Polynomial<F>, Polynomial<F>)> for RLWE<F> {
    /// Converts a tuple of polynomials into an instance of `Self`.
    ///
    /// # Arguments
    ///
    /// * `a` - The first polynomial.
    /// * `b` - The second polynomial.
    ///
    /// # Returns
    ///
    /// An instance of `Self` containing the converted polynomials.
    #[inline]
    fn from((a, b): (Polynomial<F>, Polynomial<F>)) -> Self {
        Self { a, b }
    }
}

impl<F: NTTField> From<(NTTPolynomial<F>, NTTPolynomial<F>)> for RLWE<F> {
    /// Converts a tuple of NTTPolynomials into an instance of Self.
    ///
    /// # Arguments
    ///
    /// * `a` - The first NTTPolynomial.
    /// * `b` - The second NTTPolynomial.
    ///
    /// # Returns
    ///
    /// An instance of [`RLWE<F>`].
    #[inline]
    fn from((a, b): (NTTPolynomial<F>, NTTPolynomial<F>)) -> Self {
        Self {
            a: a.into(),
            b: b.into(),
        }
    }
}

impl<F: NTTField> RLWE<F> {
    /// Creates a new [`RLWE<F>`].
    #[inline]
    pub fn new(a: Polynomial<F>, b: Polynomial<F>) -> Self {
        Self { a, b }
    }

    /// Creates a new [`RLWE<F>`] with reference of [`Polynomial<F>`].
    #[inline]
    pub fn from_ref(a: &Polynomial<F>, b: &Polynomial<F>) -> Self {
        Self {
            a: a.clone(),
            b: b.clone(),
        }
    }

    /// Creates a new [`RLWE<F>`] that is initialized to zero.
    ///
    /// The `coeff_count` parameter specifies the number of coefficients in the polynomial.
    /// Both `a` and `b` polynomials of the `RLWE<F>` are initialized with zero coefficients.
    ///
    /// # Arguments
    ///
    /// * `coeff_count` - The number of coefficients in the polynomial.
    ///
    /// # Returns
    ///
    /// A new `RLWE<F>` where both `a` and `b` polynomials are initialized to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> Self {
        Self {
            a: Polynomial::zero_with_coeff_count(coeff_count),
            b: Polynomial::zero_with_coeff_count(coeff_count),
        }
    }

    /// Returns a reference to the `a` of this [`RLWE<F>`].
    #[inline]
    pub fn a(&self) -> &Polynomial<F> {
        self.a.as_ref()
    }

    /// Returns a mutable reference to the `a` of this [`RLWE<F>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut Polynomial<F> {
        &mut self.a
    }

    /// Returns a reference to the `b` of this [`RLWE<F>`].
    #[inline]
    pub fn b(&self) -> &Polynomial<F> {
        self.b.as_ref()
    }

    /// Returns a mutable reference to the `b` of this [`RLWE<F>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut Polynomial<F> {
        &mut self.b
    }

    /// Perform element-wise addition of two [`RLWE<F>`].
    #[inline]
    pub fn add_element_wise(self, rhs: &Self) -> Self {
        Self {
            a: self.a + rhs.a(),
            b: self.b + rhs.b(),
        }
    }

    /// Perform element-wise subtraction of two [`RLWE<F>`].
    #[inline]
    pub fn sub_element_wise(self, rhs: &Self) -> Self {
        Self {
            a: self.a - rhs.a(),
            b: self.b - rhs.b(),
        }
    }

    /// Performs an in-place element-wise addition
    /// on the `self` [`RLWE<F>`] with another `rhs` [`RLWE<F>`].
    #[inline]
    pub fn add_inplace_element_wise(&mut self, rhs: &Self) {
        *self.a_mut() += rhs.a();
        *self.b_mut() += rhs.b();
    }

    /// Performs an in-place element-wise subtraction
    /// on the `self` [`RLWE<F>`] with another `rhs` [`RLWE<F>`].
    #[inline]
    pub fn sub_inplace_element_wise(&mut self, rhs: &Self) {
        *self.a_mut() -= rhs.a();
        *self.b_mut() -= rhs.b();
    }

    /// Performs a multiplication on the `self` [`RLWE<F>`] with another `poly` [`Polynomial<F>`],
    /// return a [`RLWE<F>`].
    #[inline]
    pub fn mul_with_polynomial(self, poly: &Polynomial<F>) -> Self {
        let ntt_poly = &<NTTPolynomial<F>>::from(poly);
        Self {
            a: self.a * ntt_poly,
            b: self.b * ntt_poly,
        }
    }

    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_lwe(&self) -> LWE<F> {
        let a = std::iter::once(self.a()[0])
            .chain(self.a().iter().skip(1).rev().map(|&x| -x))
            .collect();
        let b = self.b()[0];

        LWE::<F>::from((a, b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::field::{BarrettConfig, FieldDistribution};
    use rand::{
        distributions::{Standard, Uniform},
        prelude::*,
    };

    use algebra::{AlgebraRandom, Field, NTTField, Prime, Ring};

    #[derive(
        Clone,
        Copy,
        Debug,
        Default,
        Eq,
        PartialEq,
        PartialOrd,
        Ord,
        Ring,
        Field,
        AlgebraRandom,
        Prime,
        NTTField,
    )]
    #[modulus = 132120577]
    pub struct Fp32(u32);

    #[test]
    fn test_rlwe() {
        const N: usize = 8;
        let rng = &mut rand::thread_rng();

        let r: Polynomial<Fp32> =
            Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());

        let a1: Polynomial<Fp32> =
            Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
        let a2: Polynomial<Fp32> =
            Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
        let a3: Polynomial<Fp32> = &a1 * &r;

        let b1: Polynomial<Fp32> =
            Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
        let b2: Polynomial<Fp32> =
            Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
        let b3: Polynomial<Fp32> = &b1 * &r;

        let rlwe1 = RLWE::new(a1, b1);
        let rlwe2 = RLWE::new(a2, b2);
        let rlwe3 = RLWE::new(a3, b3);
        assert_eq!(
            rlwe1
                .clone()
                .add_element_wise(&rlwe2)
                .sub_element_wise(&rlwe1),
            rlwe2
        );
        assert_eq!(rlwe1.mul_with_polynomial(&r), rlwe3);
    }

    #[test]
    fn test_rlwe_he() {
        #[inline]
        fn encode(m: u32) -> Fp32 {
            Fp32::new((m as f64 * P as f64 / T as f64).round() as u32)
        }

        #[inline]
        fn decode(c: Fp32) -> u32 {
            (c.inner() as f64 * T as f64 / P as f64).round() as u32 % T
        }

        const P: u32 = Fp32::BARRETT_MODULUS.value();
        const N: usize = 1024;
        const T: u32 = 128;

        let rng = &mut rand::thread_rng();
        let chi = Fp32::normal_distribution(0., 3.2).unwrap();
        let dis = Uniform::new(0, T);

        let v0: Vec<u32> = rng.sample_iter(dis).take(N).collect();
        let v1: Vec<u32> = rng.sample_iter(dis).take(N).collect();

        let v_add: Vec<u32> = v0
            .iter()
            .zip(v1.iter())
            .map(|(a, b)| (*a + b) % T)
            .collect();

        let v0 = Polynomial::new(v0.into_iter().map(encode).collect::<Vec<Fp32>>());
        let v1 = Polynomial::new(v1.into_iter().map(encode).collect::<Vec<Fp32>>());

        let s = Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());

        let rlwe0 = {
            let a = Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
            let e = Polynomial::new(rng.sample_iter(chi).take(N).collect::<Vec<Fp32>>());
            let b = &a * &s + v0 + e;
            RLWE::new(a, b)
        };

        let rlwe1 = {
            let a = Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
            let e = Polynomial::new(rng.sample_iter(chi).take(N).collect::<Vec<Fp32>>());
            let b = &a * &s + v1 + e;
            RLWE::new(a, b)
        };

        let rlwe_add = rlwe0.add_element_wise(&rlwe1);

        let decrypted_add = (rlwe_add.b() - rlwe_add.a() * &s)
            .into_iter()
            .map(decode)
            .collect::<Vec<u32>>();

        assert_eq!(decrypted_add, v_add);
    }

    #[test]
    fn extract_lwe_test() {
        const N: usize = 8;
        let rng = &mut thread_rng();
        let s_vec: Vec<Fp32> = rng.sample_iter(Standard).take(N).collect();
        let a_vec: Vec<Fp32> = rng.sample_iter(Standard).take(N).collect();

        let s = Polynomial::from_slice(&s_vec);
        let a = Polynomial::new(a_vec);

        let b = &a * &s;

        let rlwe_sample = RLWE::new(a, b);
        let lwe_sample = rlwe_sample.extract_lwe();

        let inner_a = lwe_sample
            .a()
            .iter()
            .zip(s_vec.iter())
            .fold(Fp32::new(0), |acc, (&x, &y)| acc + x * y);

        assert_eq!(inner_a, lwe_sample.b());
    }
}
