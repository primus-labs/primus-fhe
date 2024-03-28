use std::ops::MulAssign;

use algebra::{
    ntt_add_mul_assign, ntt_add_mul_assign_fast, ntt_add_mul_inplace, ntt_mul_assign,
    ntt_mul_inplace, transformation::AbstractNTT, FieldDiscreteGaussianSampler, NTTField,
    NTTPolynomial, Polynomial, RandomNTTField,
};
use num_traits::NumCast;
use rand::{CryptoRng, Rng};
use rand_distr::Distribution;

use crate::{
    DecompositionSpace, GadgetRLWE, NTTGadgetRLWE, NTTRLWESpace, PolynomialSpace, LWE, NTTRGSW,
    RGSW,
};

/// A cryptographic structure for Ring Learning with Errors (RLWE).
/// This structure is used in advanced cryptographic systems and protocols, particularly
/// those that require efficient homomorphic encryption properties. It consists of two [`Polynomial<F>`]
/// `a` and `b` over a finite field that supports Number Theoretic Transforms (NTT), which is
/// often necessary for efficient polynomial multiplication.
///
/// The [`RLWE`] struct is generic over a type `F` which is bounded by the `NTTField` trait, ensuring
/// that the operations of addition, subtraction, and multiplication are performed in a field suitable
/// for NTT. This is crucial for the security and correctness of cryptographic operations based on RLWE.
///
/// The fields `a` and `b` are kept private within the crate to maintain encapsulation and are
/// accessible through public API functions that enforce any necessary invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RLWE<F: NTTField> {
    /// Represents the first component in the RLWE structure.
    /// It is a polynomial where the coefficients are elements of the field `F`.
    pub(crate) a: Polynomial<F>,
    /// Represents the second component in the RLWE structure.
    /// It's also a polynomial with coefficients in the field `F`.
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
    /// An instance of [`RLWE<F>`].
    #[inline]
    fn from((a, b): (Polynomial<F>, Polynomial<F>)) -> Self {
        Self { a, b }
    }
}

impl<F: NTTField> From<(NTTPolynomial<F>, NTTPolynomial<F>)> for RLWE<F> {
    /// Converts a tuple of `NTTPolynomials` into an instance of Self.
    ///
    /// # Arguments
    ///
    /// * `a` - The first `NTTPolynomial`.
    /// * `b` - The second `NTTPolynomial`.
    ///
    /// # Returns
    ///
    /// An instance of `Self` containing the converted polynomials.
    #[inline]
    fn from((a, b): (NTTPolynomial<F>, NTTPolynomial<F>)) -> Self {
        Self {
            a: <Polynomial<F>>::from(a),
            b: <Polynomial<F>>::from(b),
        }
    }
}

impl<F: NTTField> From<NTTRLWE<F>> for RLWE<F> {
    #[inline]
    fn from(ntt_rlwe: NTTRLWE<F>) -> Self {
        Self {
            a: <Polynomial<F>>::from(ntt_rlwe.a),
            b: <Polynomial<F>>::from(ntt_rlwe.b),
        }
    }
}

impl<F: NTTField> Default for RLWE<F> {
    fn default() -> Self {
        Self {
            a: Polynomial::new(Vec::new()),
            b: Polynomial::new(Vec::new()),
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
    /// Both `a` and `b` polynomials of the [`RLWE<F>`] are initialized with zero coefficients.
    ///
    /// # Arguments
    ///
    /// * `coeff_count` - The number of coefficients in the polynomial.
    ///
    /// # Returns
    ///
    /// A new [`RLWE<F>`] where both `a` and `b` polynomials are initialized to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> Self {
        Self {
            a: Polynomial::zero(coeff_count),
            b: Polynomial::zero(coeff_count),
        }
    }

    /// Returns a reference to the `a` of this [`RLWE<F>`].
    #[inline]
    pub fn a(&self) -> &Polynomial<F> {
        &self.a
    }

    /// Returns a mutable reference to the `a` of this [`RLWE<F>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut Polynomial<F> {
        &mut self.a
    }

    /// Returns a reference to the `b` of this [`RLWE<F>`].
    #[inline]
    pub fn b(&self) -> &Polynomial<F> {
        &self.b
    }

    /// Returns a mutable reference to the `b` of this [`RLWE<F>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut Polynomial<F> {
        &mut self.b
    }

    /// Returns a mutable reference to the `a` and `b` of this [`RLWE<F>`].
    #[inline]
    pub fn a_b_mut(&mut self) -> (&mut Polynomial<F>, &mut Polynomial<F>) {
        (&mut self.a, &mut self.b)
    }

    /// Extracts a slice of `a` of this [`RLWE<F>`].
    #[inline]
    pub fn a_slice(&self) -> &[F] {
        self.a.as_slice()
    }

    /// Extracts a mutable slice of `a` of this [`RLWE<F>`].
    #[inline]
    pub fn a_mut_slice(&mut self) -> &mut [F] {
        self.a.as_mut_slice()
    }

    /// Extracts a slice of `b` of this [`RLWE<F>`].
    #[inline]
    pub fn b_slice(&self) -> &[F] {
        self.b.as_slice()
    }

    /// Extracts a mutable slice of `b` of this [`RLWE<F>`].
    #[inline]
    pub fn b_mut_slice(&mut self) -> &mut [F] {
        self.b.as_mut_slice()
    }

    /// Extracts mutable slice of `a` and `b` of this [`RLWE<F>`].
    #[inline]
    pub fn a_b_mut_slices(&mut self) -> (&mut [F], &mut [F]) {
        (self.a.as_mut_slice(), self.b.as_mut_slice())
    }

    /// Perform element-wise addition of two [`RLWE<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `add_element_wise`.
    #[inline]
    pub fn add_element_wise_ref(&self, rhs: &Self) -> Self {
        Self {
            a: self.a() + rhs.a(),
            b: self.b() + rhs.b(),
        }
    }

    /// Perform element-wise addition of two [`RLWE<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is not a reference.
    /// If your `self` is a reference, you can use function `add_element_wise_ref`.
    #[inline]
    pub fn add_element_wise(self, rhs: &Self) -> Self {
        Self {
            a: self.a + rhs.a(),
            b: self.b + rhs.b(),
        }
    }

    /// Perform element-wise subtraction of two [`RLWE<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `sub_element_wise`.
    #[inline]
    pub fn sub_element_wise_ref(&self, rhs: &Self) -> Self {
        Self {
            a: self.a() - rhs.a(),
            b: self.b() - rhs.b(),
        }
    }

    /// Perform element-wise subtraction of two [`RLWE<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is not a reference.
    /// If your `self` is a reference, you can use function `sub_element_wise_ref`.
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
    pub fn add_assign_element_wise(&mut self, rhs: &Self) {
        self.a += rhs.a();
        self.b += rhs.b();
    }

    /// Performs an in-place element-wise subtraction
    /// on the `self` [`RLWE<F>`] with another `rhs` [`RLWE<F>`].
    #[inline]
    pub fn sub_assign_element_wise(&mut self, rhs: &Self) {
        self.a -= rhs.a();
        self.b -= rhs.b();
    }

    /// Performs a multiplication on the `self` [`RLWE<F>`] with another `ntt_polynomial` [`NTTPolynomial<F>`],
    /// store the result into `destination` [`NTTRLWE<F>`].
    #[inline]
    pub fn mul_ntt_polynomial_inplace(
        &self,
        ntt_polynomial: &NTTPolynomial<F>,
        destination: &mut NTTRLWE<F>,
    ) {
        let coeff_count = ntt_polynomial.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());

        let log_n = coeff_count.trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();

        let (a, b) = destination.a_b_mut();

        a.copy_from(self.a());
        b.copy_from(self.b());

        ntt_table.transform_slice(a.as_mut_slice());
        ntt_table.transform_slice(b.as_mut_slice());

        ntt_mul_assign(a, ntt_polynomial);
        ntt_mul_assign(b, ntt_polynomial);
    }

    /// Performs `self + gadget_rlwe * polynomial`.
    #[inline]
    pub fn add_gadget_rlwe_mul_polynomial(
        self,
        gadget_rlwe: &GadgetRLWE<F>,
        polynomial: &Polynomial<F>,
    ) -> RLWE<F> {
        gadget_rlwe.mul_polynomial_add_rlwe(polynomial, self)
    }

    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_lwe(&self) -> LWE<F> {
        let mut a: Vec<F> = self.a.as_slice().iter().map(|&x| -x).collect();
        a[1..].reverse();
        a[0] = -a[0];

        let b = self.b()[0];

        LWE::<F>::new(a, b)
    }

    /// Perform `self = self + rhs * Y^r` for functional bootstrapping where `Y = X^(2N/q)`.
    pub fn add_assign_rhs_mul_monic_monomial<T: NumCast>(
        &mut self,
        rhs: &Self,
        // N
        rlwe_dimension: usize,
        // 2N/q
        twice_rlwe_dimension_div_lwe_modulus: usize,
        r: T,
    ) {
        let r = num_traits::cast::<T, usize>(r).unwrap() * twice_rlwe_dimension_div_lwe_modulus;
        if r <= rlwe_dimension {
            #[inline]
            fn rotate_add<F: NTTField>(
                x: &mut Polynomial<F>,
                y: &Polynomial<F>,
                r: usize,
                n_sub_r: usize,
            ) {
                x[0..r]
                    .iter_mut()
                    .zip(y[n_sub_r..].iter())
                    .for_each(|(u, v)| *u -= v);
                x[r..]
                    .iter_mut()
                    .zip(y[0..n_sub_r].iter())
                    .for_each(|(u, v)| *u += v);
            }
            let n_sub_r = rlwe_dimension - r;
            rotate_add(self.a_mut(), rhs.a(), r, n_sub_r);
            rotate_add(self.b_mut(), rhs.b(), r, n_sub_r);
        } else {
            #[inline]
            fn rotate_add<F: NTTField>(
                x: &mut Polynomial<F>,
                y: &Polynomial<F>,
                r: usize,
                n_sub_r: usize,
            ) {
                x[0..r]
                    .iter_mut()
                    .zip(y[n_sub_r..].iter())
                    .for_each(|(u, v)| *u += v);
                x[r..]
                    .iter_mut()
                    .zip(y[0..n_sub_r].iter())
                    .for_each(|(u, v)| *u -= v);
            }
            let r = r - rlwe_dimension;
            let n_sub_r = rlwe_dimension - r;
            rotate_add(self.a_mut(), rhs.a(), r, n_sub_r);
            rotate_add(self.b_mut(), rhs.b(), r, n_sub_r);
        }
    }

    /// Performs a multiplication on the `self` [`RLWE<F>`] with another `small_rgsw` [`RGSW<F>`],
    /// return a [`RLWE<F>`].
    ///
    /// # Attention
    /// The message of **`small_rgsw`** is restricted to small messages `m`, typically `m = ±Xⁱ`
    #[inline]
    pub fn mul_small_rgsw(&self, small_rgsw: &RGSW<F>) -> RLWE<F> {
        small_rgsw
            .c_neg_s_m()
            .mul_polynomial(self.a())
            .add_gadget_rlwe_mul_polynomial(small_rgsw.c_m(), self.b())
    }

    /// Performs a multiplication on the `self` [`RLWE<F>`] with another `small_ntt_rgsw` [`NTTRGSW<F>`],
    /// return a [`RLWE<F>`].
    ///
    /// # Attention
    /// The message of **`small_ntt_rgsw`** is restricted to small messages `m`, typically `m = ±Xⁱ`
    #[inline]
    pub fn mul_small_ntt_rgsw(&self, small_ntt_rgsw: &NTTRGSW<F>) -> RLWE<F> {
        small_ntt_rgsw
            .c_neg_s_m()
            .mul_polynomial(self.a())
            .add_gadget_rlwe_mul_polynomial(small_ntt_rgsw.c_m(), self.b())
            .into()
    }

    /// Performs a multiplication on the `self` [`RLWE<F>`] with another `small_ntt_rgsw` [`NTTRGSW<F>`],
    /// output the [`RLWE<F>`] result into `destination`.
    ///
    /// # Attention
    /// The message of **`small_ntt_rgsw`** is restricted to small messages `m`, typically `m = ±Xⁱ`
    #[inline]
    pub fn mul_small_ntt_rgsw_inplace(
        &self,
        small_ntt_rgsw: &NTTRGSW<F>,
        // Pre allocate space
        decompose_space: &mut DecompositionSpace<F>,
        polynomial_space: &mut PolynomialSpace<F>,
        median: &mut NTTRLWESpace<F>,
        // Output destination
        destination: &mut RLWE<F>,
    ) {
        small_ntt_rgsw.c_neg_s_m().mul_polynomial_inplace_fast(
            self.a(),
            decompose_space,
            polynomial_space,
            median,
        );

        median.add_assign_gadget_rlwe_mul_polynomial_inplace_fast(
            small_ntt_rgsw.c_m(),
            self.b(),
            decompose_space,
            polynomial_space,
        );

        median.inverse_transform_inplace(destination)
    }
}

impl<F: RandomNTTField> RLWE<F> {
    /// Generate a `RLWE<F>` sample which encrypts `0`.
    pub fn generate_random_zero_sample<R>(
        rlwe_dimension: usize,
        secret_key: &NTTPolynomial<F>,
        error_sampler: FieldDiscreteGaussianSampler,
        mut rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
        FieldDiscreteGaussianSampler: Distribution<F>,
    {
        let a = <Polynomial<F>>::random(rlwe_dimension, &mut rng);

        let mut a_ntt = a.clone().into_ntt_polynomial();
        a_ntt *= secret_key;

        let mut e = <Polynomial<F>>::random_with_gaussian(rlwe_dimension, &mut rng, error_sampler);
        e += a_ntt.into_native_polynomial();

        Self { a, b: e }
    }

    /// Generate a `RLWE<F>` sample which encrypts `0`.
    pub fn generate_random_zero_sample_slower<R>(
        rlwe_dimension: usize,
        secret_key: &Polynomial<F>,
        error_sampler: FieldDiscreteGaussianSampler,
        mut rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
        FieldDiscreteGaussianSampler: Distribution<F>,
    {
        let a = <Polynomial<F>>::random(rlwe_dimension, &mut rng);

        let mut a_ntt = a.clone().into_ntt_polynomial();
        a_ntt *= secret_key;

        let mut e = <Polynomial<F>>::random_with_gaussian(rlwe_dimension, &mut rng, error_sampler);
        e += a_ntt.into_native_polynomial();

        Self { a, b: e }
    }
}

/// A cryptographic structure for Ring Learning with Errors (RLWE).
/// This structure is used in advanced cryptographic systems and protocols, particularly
/// those that require efficient homomorphic encryption properties. It consists of two [`NTTPolynomial<F>`]
/// `a` and `b` over a finite field that supports Number Theoretic Transforms (NTT), which is
/// often necessary for efficient polynomial multiplication.
///
/// The [`NTTRLWE`] struct is generic over a type `F` which is bounded by the `NTTField` trait, ensuring
/// that the operations of addition, subtraction, and multiplication are performed in a field suitable
/// for NTT. This is crucial for the security and correctness of cryptographic operations based on RLWE.
///
/// The fields `a` and `b` are kept private within the crate to maintain encapsulation and are
/// accessible through public API functions that enforce any necessary invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NTTRLWE<F: NTTField> {
    /// Represents the first component in the RLWE structure.
    pub(crate) a: NTTPolynomial<F>,
    /// Represents the second component in the RLWE structure.
    pub(crate) b: NTTPolynomial<F>,
}

impl<F: NTTField> From<RLWE<F>> for NTTRLWE<F> {
    #[inline]
    fn from(rlwe: RLWE<F>) -> Self {
        Self {
            a: <NTTPolynomial<F>>::from(rlwe.a),
            b: <NTTPolynomial<F>>::from(rlwe.b),
        }
    }
}

impl<F: NTTField> From<(Polynomial<F>, Polynomial<F>)> for NTTRLWE<F> {
    #[inline]
    fn from((a, b): (Polynomial<F>, Polynomial<F>)) -> Self {
        Self {
            a: <NTTPolynomial<F>>::from(a),
            b: <NTTPolynomial<F>>::from(b),
        }
    }
}

impl<F: NTTField> NTTRLWE<F> {
    /// Creates a new [`NTTRLWE<F>`].
    #[inline]
    pub fn new(a: NTTPolynomial<F>, b: NTTPolynomial<F>) -> Self {
        Self { a, b }
    }

    /// Creates a new [`NTTRLWE<F>`] with reference of [`NTTPolynomial<F>`].
    #[inline]
    pub fn from_ref(a: &NTTPolynomial<F>, b: &NTTPolynomial<F>) -> Self {
        Self {
            a: a.clone(),
            b: b.clone(),
        }
    }

    /// Creates a [`NTTRLWE<F>`] with all entries equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> NTTRLWE<F> {
        Self {
            a: <NTTPolynomial<F>>::zero(coeff_count),
            b: <NTTPolynomial<F>>::zero(coeff_count),
        }
    }

    /// Set all entries equal to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.a.set_zero();
        self.b.set_zero();
    }

    /// ntt inverse transform
    pub fn inverse_transform_inplace(&self, destination: &mut RLWE<F>) {
        let coeff_count = destination.a.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();

        let (a, b) = destination.a_b_mut_slices();

        a.copy_from_slice(self.a_slice());
        b.copy_from_slice(self.b_slice());

        ntt_table.inverse_transform_slice(a);
        ntt_table.inverse_transform_slice(b);
    }

    /// Returns a reference to the a of this [`NTTRLWE<F>`].
    #[inline]
    pub fn a(&self) -> &NTTPolynomial<F> {
        &self.a
    }

    /// Returns a mutable reference to the a of this [`NTTRLWE<F>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut NTTPolynomial<F> {
        &mut self.a
    }

    /// Returns a reference to the b of this [`NTTRLWE<F>`].
    #[inline]
    pub fn b(&self) -> &NTTPolynomial<F> {
        &self.b
    }

    /// Returns a mutable reference to the b of this [`NTTRLWE<F>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut NTTPolynomial<F> {
        &mut self.b
    }

    /// Returns a mutable reference to the `a` and `b` of this [`NTTRLWE<F>`].
    #[inline]
    pub fn a_b_mut(&mut self) -> (&mut NTTPolynomial<F>, &mut NTTPolynomial<F>) {
        (&mut self.a, &mut self.b)
    }

    /// Extracts a slice of `a` of this [`NTTRLWE<F>`].
    #[inline]
    pub fn a_slice(&self) -> &[F] {
        self.a.as_slice()
    }

    /// Extracts a mutable slice of `a` of this [`NTTRLWE<F>`].
    #[inline]
    pub fn a_mut_slice(&mut self) -> &mut [F] {
        self.a.as_mut_slice()
    }

    /// Extracts a slice of `b` of this [`NTTRLWE<F>`].
    #[inline]
    pub fn b_slice(&self) -> &[F] {
        self.b.as_slice()
    }

    /// Extracts a mutable slice of `b` of this [`NTTRLWE<F>`].
    #[inline]
    pub fn b_mut_slice(&mut self) -> &mut [F] {
        self.b.as_mut_slice()
    }

    /// Extracts mutable slice of `a` and `b` of this [`NTTRLWE<F>`].
    #[inline]
    pub fn a_b_mut_slices(&mut self) -> (&mut [F], &mut [F]) {
        (self.a.as_mut_slice(), self.b.as_mut_slice())
    }

    /// Perform element-wise addition of two [`NTTRLWE<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `add_element_wise`.
    #[inline]
    pub fn add_element_wise_ref(&self, rhs: &Self) -> Self {
        Self {
            a: self.a() + rhs.a(),
            b: self.b() + rhs.b(),
        }
    }

    /// Perform element-wise addition of two [`NTTRLWE<F>`].
    #[inline]
    pub fn add_element_wise(self, rhs: &Self) -> Self {
        Self {
            a: self.a + rhs.a(),
            b: self.b + rhs.b(),
        }
    }

    /// Perform element-wise subtraction of two [`NTTRLWE<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `sub_element_wise`.
    #[inline]
    pub fn sub_element_wise_ref(&self, rhs: &Self) -> Self {
        Self {
            a: self.a() - rhs.a(),
            b: self.b() - rhs.b(),
        }
    }

    /// Perform element-wise subtraction of two [`NTTRLWE<F>`].
    #[inline]
    pub fn sub_element_wise(self, rhs: &Self) -> Self {
        Self {
            a: self.a - rhs.a(),
            b: self.b - rhs.b(),
        }
    }

    /// Performs an in-place element-wise addition
    /// on the `self` [`NTTRLWE<F>`] with another `rhs` [`NTTRLWE<F>`].
    #[inline]
    pub fn add_element_wise_assign(&mut self, rhs: &Self) {
        self.a += rhs.a();
        self.b += rhs.b();
    }

    /// Performs an in-place element-wise subtraction
    /// on the `self` [`NTTRLWE<F>`] with another `rhs` [`NTTRLWE<F>`].
    #[inline]
    pub fn sub_element_wise_assign(&mut self, rhs: &Self) {
        self.a -= rhs.a();
        self.b -= rhs.b();
    }

    /// Performs a multiplication on the `self` [`NTTRLWE<F>`] with another `ntt_polynomial` [`NTTPolynomial<F>`].
    #[inline]
    pub fn mul_ntt_polynomial_assign(&mut self, ntt_polynomial: &NTTPolynomial<F>) {
        self.a.mul_assign(ntt_polynomial);
        self.b.mul_assign(ntt_polynomial);
    }

    /// Performs a multiplication on the `self` [`NTTRLWE<F>`] with another `polynomial` [`NTTPolynomial<F>`],
    /// stores the result into `destination`.
    #[inline]
    pub fn mul_ntt_polynomial_inplace(
        &self,
        ntt_polynomial: &NTTPolynomial<F>,
        destination: &mut NTTRLWE<F>,
    ) {
        ntt_mul_inplace(self.a(), ntt_polynomial, destination.a_mut());
        ntt_mul_inplace(self.b(), ntt_polynomial, destination.b_mut());
    }

    /// Performs `self = self + ntt_rlwe * ntt_polynomial`.
    #[inline]
    pub fn add_ntt_rlwe_mul_ntt_polynomial_assign(
        &mut self,
        ntt_rlwe: &NTTRLWE<F>,
        ntt_polynomial: &NTTPolynomial<F>,
    ) {
        ntt_add_mul_assign(self.a_mut(), ntt_rlwe.a(), ntt_polynomial);
        ntt_add_mul_assign(self.b_mut(), ntt_rlwe.b(), ntt_polynomial);
    }

    /// Performs `self = self + ntt_rlwe * ntt_polynomial`.
    ///
    /// The result coefficients may be in [0, 2*modulus) for some case,
    /// and fall back to [0, modulus) for normal case,
    #[inline]
    pub fn add_ntt_rlwe_mul_ntt_polynomial_assign_fast(
        &mut self,
        ntt_rlwe: &NTTRLWE<F>,
        ntt_polynomial: &NTTPolynomial<F>,
    ) {
        ntt_add_mul_assign_fast(self.a_mut(), ntt_rlwe.a(), ntt_polynomial);
        ntt_add_mul_assign_fast(self.b_mut(), ntt_rlwe.b(), ntt_polynomial);
    }

    /// Performs `destination = self + ntt_rlwe * ntt_polynomial`.
    #[inline]
    pub fn add_ntt_rlwe_mul_ntt_polynomial_inplace(
        &self,
        ntt_rlwe: &Self,
        ntt_polynomial: &NTTPolynomial<F>,
        destination: &mut Self,
    ) {
        ntt_add_mul_inplace(self.a(), ntt_rlwe.a(), ntt_polynomial, destination.a_mut());
        ntt_add_mul_inplace(self.b(), ntt_rlwe.b(), ntt_polynomial, destination.b_mut());
    }

    /// Performs `self + gadget_rlwe * polynomial`.
    #[inline]
    pub fn add_gadget_rlwe_mul_polynomial(
        mut self,
        gadget_rlwe: &NTTGadgetRLWE<F>,
        polynomial: &Polynomial<F>,
    ) -> NTTRLWE<F> {
        let coeff_count = polynomial.coeff_count();
        let mut decompose_space = DecompositionSpace::new(coeff_count);
        let mut polynomial_space = PolynomialSpace::new(coeff_count);

        self.add_assign_gadget_rlwe_mul_polynomial_inplace(
            gadget_rlwe,
            polynomial,
            &mut decompose_space,
            &mut polynomial_space,
        );
        self
    }

    /// Performs `self = self + gadget_rlwe * polynomial`.
    #[inline]
    pub fn add_assign_gadget_rlwe_mul_polynomial_inplace(
        &mut self,
        gadget_rlwe: &NTTGadgetRLWE<F>,
        polynomial: &Polynomial<F>,
        decompose_space: &mut DecompositionSpace<F>,
        polynomial_space: &mut PolynomialSpace<F>,
    ) {
        let coeff_count = polynomial.coeff_count();
        debug_assert_eq!(coeff_count, polynomial_space.coeff_count());
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();
        let basis = gadget_rlwe.basis();

        polynomial_space.copy_from(polynomial);

        let mut ntt_polynomial = NTTPolynomial::new(Vec::new());

        gadget_rlwe.iter().for_each(|g| {
            polynomial_space.decompose_lsb_bits_inplace(basis, decompose_space);
            ntt_table.transform_slice(decompose_space.as_mut_slice());

            std::mem::swap(decompose_space.data_mut(), ntt_polynomial.data_mut());
            self.add_ntt_rlwe_mul_ntt_polynomial_assign(g, &ntt_polynomial);
            std::mem::swap(decompose_space.data_mut(), ntt_polynomial.data_mut());
        })
    }

    /// Performs `self = self + gadget_rlwe * polynomial`.
    ///
    /// The result coefficients may be in [0, 2*modulus) for some case,
    /// and fall back to [0, modulus) for normal case,
    #[inline]
    pub fn add_assign_gadget_rlwe_mul_polynomial_inplace_fast(
        &mut self,
        gadget_rlwe: &NTTGadgetRLWE<F>,
        polynomial: &Polynomial<F>,
        decompose_space: &mut DecompositionSpace<F>,
        polynomial_space: &mut PolynomialSpace<F>,
    ) {
        let coeff_count = polynomial.coeff_count();
        debug_assert_eq!(coeff_count, polynomial_space.coeff_count());
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();
        let basis = gadget_rlwe.basis();

        polynomial_space.copy_from(polynomial);

        let mut ntt_polynomial = NTTPolynomial::new(Vec::new());

        gadget_rlwe.iter().for_each(|g| {
            polynomial_space.decompose_lsb_bits_inplace(basis, decompose_space);
            ntt_table.transform_slice(decompose_space.as_mut_slice());

            std::mem::swap(decompose_space.data_mut(), ntt_polynomial.data_mut());
            self.add_ntt_rlwe_mul_ntt_polynomial_assign_fast(g, &ntt_polynomial);
            std::mem::swap(decompose_space.data_mut(), ntt_polynomial.data_mut());
        })
    }

    /// Performs `self = self - gadget_rlwe * polynomial`.
    #[inline]
    pub fn sub_assign_gadget_rlwe_mul_polynomial_inplace(
        &mut self,
        gadget_rlwe: &NTTGadgetRLWE<F>,
        polynomial: Polynomial<F>,
        decompose_space: &mut DecompositionSpace<F>,
    ) {
        let coeff_count = polynomial.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();
        let decompose_space = decompose_space.get_mut();
        let basis = gadget_rlwe.basis();

        let mut polynomial = -polynomial;

        let mut ntt_polynomial = NTTPolynomial::new(Vec::new());

        gadget_rlwe.iter().for_each(|g| {
            polynomial.decompose_lsb_bits_inplace(basis, decompose_space);
            ntt_table.transform_slice(decompose_space.as_mut_slice());

            std::mem::swap(decompose_space.data_mut(), ntt_polynomial.data_mut());
            self.add_ntt_rlwe_mul_ntt_polynomial_assign(g, &ntt_polynomial);
            std::mem::swap(decompose_space.data_mut(), ntt_polynomial.data_mut());
        })
    }

    /// Performs `self = self - gadget_rlwe * polynomial`.
    ///
    /// The result coefficients may be in [0, 2*modulus) for some case,
    /// and fall back to [0, modulus) for normal case,
    #[inline]
    pub fn sub_assign_gadget_rlwe_mul_polynomial_inplace_fast(
        &mut self,
        gadget_rlwe: &NTTGadgetRLWE<F>,
        polynomial: Polynomial<F>,
        decompose_space: &mut DecompositionSpace<F>,
    ) {
        let coeff_count = polynomial.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();
        let decompose_space = decompose_space.get_mut();
        let basis = gadget_rlwe.basis();

        let mut polynomial = -polynomial;

        let mut ntt_polynomial = NTTPolynomial::new(Vec::new());

        gadget_rlwe.iter().for_each(|g| {
            polynomial.decompose_lsb_bits_inplace(basis, decompose_space);
            ntt_table.transform_slice(decompose_space.as_mut_slice());

            std::mem::swap(decompose_space.data_mut(), ntt_polynomial.data_mut());
            self.add_ntt_rlwe_mul_ntt_polynomial_assign_fast(g, &ntt_polynomial);
            std::mem::swap(decompose_space.data_mut(), ntt_polynomial.data_mut());
        })
    }
}

impl<F: RandomNTTField> NTTRLWE<F> {
    /// Generate a `NTTRLWE<F>` sample which encrypts `0`.
    pub fn generate_random_zero_sample<R>(
        rlwe_dimension: usize,
        secret_key: &NTTPolynomial<F>,
        error_sampler: FieldDiscreteGaussianSampler,
        mut rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
        FieldDiscreteGaussianSampler: Distribution<F>,
    {
        let a = <NTTPolynomial<F>>::random(rlwe_dimension, &mut rng);
        let mut e = <Polynomial<F>>::random_with_gaussian(rlwe_dimension, &mut rng, error_sampler)
            .into_ntt_polynomial();
        ntt_add_mul_assign(&mut e, &a, secret_key);

        Self { a, b: e }
    }

    /// Generate a `NTTRLWE<F>` sample which encrypts `value`.
    pub fn generate_random_value_sample<R>(
        rlwe_dimension: usize,
        secret_key: &NTTPolynomial<F>,
        value: F,
        error_sampler: FieldDiscreteGaussianSampler,
        mut rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
        FieldDiscreteGaussianSampler: Distribution<F>,
    {
        let a = <NTTPolynomial<F>>::random(rlwe_dimension, &mut rng);

        let mut e = <Polynomial<F>>::random_with_gaussian(rlwe_dimension, &mut rng, error_sampler);
        e[0] += value;

        let mut b = e.into_ntt_polynomial();
        ntt_add_mul_assign(&mut b, &a, secret_key);

        Self { a, b }
    }
}
