use std::slice::{Iter, IterMut};

use algebra::{
    transformation::AbstractNTT, Basis, FieldDiscreteGaussianSampler, NTTField, NTTPolynomial,
    Polynomial,
};
use rand::{CryptoRng, Rng};

use crate::{DecompositionSpace, PolynomialSpace, NTTRLWE, RLWE};

/// A representation of Ring Learning with Errors (RLWE) ciphertexts with respect to different powers
/// of a base, used to control noise growth in polynomial multiplications.
///
/// [`GadgetRLWE`] stores a sequence of [`RLWE`] ciphertexts where each [`RLWE<F>`] instance within
/// the `data` vector represents a ciphertext of a scaled version of a message `m` by successive
/// powers of the `basis`. The first element of `data` is the ciphertext of `m`, the second is `basis * m`,
/// the third is `basis^2 * m`, and so on. This is particularly useful in cryptographic operations
/// where reducing the noise growth during the multiplication of RLWE ciphertexts with polynomials is crucial.
///
/// The struct is generic over a type `F` that must implement the [`NTTField`] trait, which ensures that
/// the field operations are compatible with Number Theoretic Transforms, a key requirement for
/// efficient polynomial operations in RLWE-based cryptography.
#[derive(Debug, Clone)]
pub struct GadgetRLWE<F: NTTField> {
    /// A vector of RLWE ciphertexts, each encrypted message with a different power of the `basis`.
    data: Vec<RLWE<F>>,
    /// The base with respect to which the ciphertexts are scaled.
    basis: Basis<F>,
}

impl<F: NTTField> From<(Vec<RLWE<F>>, Basis<F>)> for GadgetRLWE<F> {
    #[inline]
    fn from((data, basis): (Vec<RLWE<F>>, Basis<F>)) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_len());
        Self { data, basis }
    }
}

impl<F: NTTField> GadgetRLWE<F> {
    /// Creates a new [`GadgetRLWE<F>`].
    #[inline]
    pub fn new(data: Vec<RLWE<F>>, basis: Basis<F>) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_len());
        Self { data, basis }
    }

    /// Creates a new [`GadgetRLWE<F>`] with reference.
    #[inline]
    pub fn from_ref(data: &[RLWE<F>], basis: Basis<F>) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_len());
        Self {
            data: data.to_vec(),
            basis,
        }
    }

    /// Returns a reference to the `data` of this [`GadgetRLWE<F>`].
    #[inline]
    pub fn data(&self) -> &[RLWE<F>] {
        self.data.as_ref()
    }

    /// Returns the basis of this [`GadgetRLWE<F>`].
    #[inline]
    pub fn basis(&self) -> Basis<F> {
        self.basis
    }

    /// Returns an iterator over the `data` of this [`GadgetRLWE<F>`].
    #[inline]
    pub fn iter(&self) -> Iter<'_, RLWE<F>> {
        self.data.iter()
    }

    /// Returns an iterator over the `data` of this [`GadgetRLWE<F>`]
    /// that allows modifying each value.
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, RLWE<F>> {
        self.data.iter_mut()
    }

    /// Perform multiplication between [`GadgetRLWE<F>`] and [`Polynomial<F>`],
    /// return a [`RLWE<F>`].
    pub fn mul_polynomial(&self, polynomial: &Polynomial<F>) -> RLWE<F> {
        let coeff_count = polynomial.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();

        let mut decompose_space = DecompositionSpace::new(coeff_count);
        let mut polynomial = polynomial.clone();

        let mut ntt_rlwe = <NTTRLWE<F>>::zero(coeff_count);
        let mut temp = <NTTRLWE<F>>::zero(coeff_count);

        let space = decompose_space.get_mut();

        let mut ntt_polynomial = NTTPolynomial::new(Vec::new());

        self.iter().for_each(|g| {
            polynomial.decompose_lsb_bits_inplace(self.basis, space);
            ntt_table.transform_slice(space.as_mut_slice());

            std::mem::swap(space.data_mut(), ntt_polynomial.data_mut());
            g.mul_ntt_polynomial_inplace(&ntt_polynomial, &mut temp);
            std::mem::swap(space.data_mut(), ntt_polynomial.data_mut());

            ntt_rlwe.add_element_wise_assign(&temp);
        });
        <RLWE<F>>::from(ntt_rlwe)
    }

    /// Perform multiplication between [`GadgetRLWE<F>`] and [`Polynomial<F>`],
    /// then add the `rlwe`, return a [`RLWE<F>`].
    pub fn mul_polynomial_add_rlwe(&self, polynomial: &Polynomial<F>, rlwe: RLWE<F>) -> RLWE<F> {
        let coeff_count = polynomial.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();

        let mut decompose_space = DecompositionSpace::new(coeff_count);
        let mut polynomial = polynomial.clone();

        let mut ntt_rlwe = <NTTRLWE<F>>::from(rlwe);
        let mut temp = <NTTRLWE<F>>::zero(coeff_count);

        let space = decompose_space.get_mut();
        let mut ntt_polynomial = NTTPolynomial::new(Vec::new());

        self.iter().for_each(|g| {
            polynomial.decompose_lsb_bits_inplace(self.basis, space);
            ntt_table.transform_slice(space.as_mut_slice());

            std::mem::swap(space.data_mut(), ntt_polynomial.data_mut());
            g.mul_ntt_polynomial_inplace(&ntt_polynomial, &mut temp);
            std::mem::swap(space.data_mut(), ntt_polynomial.data_mut());

            ntt_rlwe.add_element_wise_assign(&temp);
        });
        <RLWE<F>>::from(ntt_rlwe)
    }
}

impl<F: NTTField> GadgetRLWE<F> {
    /// Generate a `GadgetRLWE<F>` sample which encrypts `0`.
    pub fn generate_random_zero_sample<R>(
        secret_key: &NTTPolynomial<F>,
        basis: Basis<F>,
        error_sampler: FieldDiscreteGaussianSampler,
        mut rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let data = (0..basis.decompose_len())
            .map(|_| <RLWE<F>>::generate_random_zero_sample(secret_key, error_sampler, &mut rng))
            .collect();
        Self { data, basis }
    }

    /// Generate a `GadgetRLWE<F>` sample which encrypts `1`.
    pub fn generate_random_one_sample<R>(
        secret_key: &NTTPolynomial<F>,
        basis: Basis<F>,
        error_sampler: FieldDiscreteGaussianSampler,
        mut rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let len = basis.decompose_len();
        let basis_value = basis.basis();
        let mut basis_power = F::ONE;
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            let mut r = <RLWE<F>>::generate_random_zero_sample(secret_key, error_sampler, &mut rng);
            r.b_mut_slice()[0] += basis_power;
            data.push(r);
            basis_power = F::new(basis_power.get() * basis_value);
        }

        Self { data, basis }
    }

    /// Generate a `GadgetRLWE<F>` sample which encrypts `-s`.
    pub fn generate_random_neg_secret_sample<R>(
        secret_key: &NTTPolynomial<F>,
        basis: Basis<F>,
        error_sampler: FieldDiscreteGaussianSampler,
        mut rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let len = basis.decompose_len();
        let basis_value = basis.basis();
        let mut basis_power = F::ONE;
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            let mut r = <RLWE<F>>::generate_random_zero_sample(secret_key, error_sampler, &mut rng);
            r.a_mut_slice()[0] += basis_power;
            data.push(r);
            basis_power = F::new(basis_power.get() * basis_value);
        }

        Self { data, basis }
    }
}

/// A representation of Ring Learning with Errors (RLWE) ciphertexts with respect to different powers
/// of a base, used to control noise growth in polynomial multiplications.
///
/// [`NTTGadgetRLWE`] stores a sequence of [`NTTRLWE`] ciphertexts where each [`NTTRLWE<F>`] instance within
/// the `data` vector represents a ciphertext of a scaled version of a message `m` by successive
/// powers of the `basis`. The first element of `data` is the ciphertext of `m`, the second is `basis * m`,
/// the third is `basis^2 * m`, and so on. This is particularly useful in cryptographic operations
/// where reducing the noise growth during the multiplication of RLWE ciphertexts with polynomials is crucial.
///
/// The struct is generic over a type `F` that must implement the [`NTTField`] trait, which ensures that
/// the field operations are compatible with Number Theoretic Transforms, a key requirement for
/// efficient polynomial operations in RLWE-based cryptography.
#[derive(Debug, Clone)]
pub struct NTTGadgetRLWE<F: NTTField> {
    /// A vector of NTT RLWE ciphertexts, each encrypted message with a different power of the `basis`.
    data: Vec<NTTRLWE<F>>,
    /// The base with respect to which the ciphertexts are scaled.
    basis: Basis<F>,
}

impl<F: NTTField> From<GadgetRLWE<F>> for NTTGadgetRLWE<F> {
    #[inline]
    fn from(g: GadgetRLWE<F>) -> Self {
        Self {
            data: g.data.into_iter().map(<NTTRLWE<F>>::from).collect(),
            basis: g.basis,
        }
    }
}

impl<F: NTTField> From<(Vec<NTTRLWE<F>>, Basis<F>)> for NTTGadgetRLWE<F> {
    #[inline]
    fn from((data, basis): (Vec<NTTRLWE<F>>, Basis<F>)) -> Self {
        Self { data, basis }
    }
}

impl<F: NTTField> NTTGadgetRLWE<F> {
    /// Creates a new [`NTTGadgetRLWE<F>`].
    #[inline]
    pub fn new(data: Vec<NTTRLWE<F>>, basis: Basis<F>) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_len());
        Self { data, basis }
    }

    /// Creates a new [`NTTGadgetRLWE<F>`] with reference.
    #[inline]
    pub fn from_ref(data: &[NTTRLWE<F>], basis: Basis<F>) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_len());
        Self {
            data: data.to_vec(),
            basis,
        }
    }

    /// Creates a [`NTTGadgetRLWE<F>`] with all entries equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize, basis: Basis<F>) -> Self {
        Self {
            data: (0..basis.decompose_len())
                .map(|_| NTTRLWE::zero(coeff_count))
                .collect(),
            basis,
        }
    }

    /// Set all entries equal to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.data.iter_mut().for_each(|rlwe| rlwe.set_zero());
    }

    /// Returns a reference to the data of this [`NTTGadgetRLWE<F>`].
    #[inline]
    pub fn data(&self) -> &[NTTRLWE<F>] {
        self.data.as_ref()
    }

    /// Returns the basis of this [`NTTGadgetRLWE<F>`].
    #[inline]
    pub fn basis(&self) -> Basis<F> {
        self.basis
    }

    /// Returns an iterator over the `data` of this [`NTTGadgetRLWE<F>`].
    #[inline]
    pub fn iter(&self) -> Iter<'_, NTTRLWE<F>> {
        self.data.iter()
    }

    /// Returns an iterator over the `data` of this [`NTTGadgetRLWE<F>`]
    /// that allows modifying each value.
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, NTTRLWE<F>> {
        self.data.iter_mut()
    }

    /// Perform multiplication between [`NTTGadgetRLWE<F>`] and [`Polynomial<F>`],
    /// return a [`NTTRLWE<F>`].
    pub fn mul_polynomial(&self, polynomial: &Polynomial<F>) -> NTTRLWE<F> {
        let coeff_count = polynomial.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();

        let mut decompose_space = DecompositionSpace::new(coeff_count);
        let mut polynomial = polynomial.clone();

        let mut ntt_rlwe = <NTTRLWE<F>>::zero(coeff_count);

        let space = decompose_space.get_mut();

        let mut ntt_polynomial = NTTPolynomial::new(Vec::new());

        self.iter().for_each(|g| {
            polynomial.decompose_lsb_bits_inplace(self.basis, space);
            ntt_table.transform_slice(space.as_mut_slice());

            std::mem::swap(space.data_mut(), ntt_polynomial.data_mut());
            ntt_rlwe.add_ntt_rlwe_mul_ntt_polynomial_assign(g, &ntt_polynomial);
            std::mem::swap(space.data_mut(), ntt_polynomial.data_mut());
        });

        ntt_rlwe
    }

    /// Perform multiplication between [`NTTGadgetRLWE<F>`] and [`Polynomial<F>`],
    /// stores the result into `destination`.
    pub fn mul_polynomial_inplace(
        &self,
        polynomial: &Polynomial<F>,
        // Pre allocate space for decomposition
        decompose_space: &mut DecompositionSpace<F>,
        polynomial_space: &mut PolynomialSpace<F>,
        // Output destination
        destination: &mut NTTRLWE<F>,
    ) {
        let coeff_count = polynomial.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();

        polynomial_space.copy_from(polynomial);

        destination.set_zero();

        let mut ntt_polynomial = NTTPolynomial::new(Vec::new());

        self.iter().for_each(|g_rlwe| {
            polynomial_space.decompose_lsb_bits_inplace(self.basis, decompose_space);
            ntt_table.transform_slice(decompose_space.as_mut_slice());

            std::mem::swap(decompose_space.data_mut(), ntt_polynomial.data_mut());
            destination.add_ntt_rlwe_mul_ntt_polynomial_assign(g_rlwe, &ntt_polynomial);
            std::mem::swap(decompose_space.data_mut(), ntt_polynomial.data_mut());
        })
    }

    /// Perform multiplication between [`NTTGadgetRLWE<F>`] and [`Polynomial<F>`],
    /// stores the result into `destination`.
    ///
    /// The coefficients in the `destination` may be in [0, 2*modulus) for some case,
    /// and fall back to [0, modulus) for normal case,
    pub fn mul_polynomial_inplace_fast(
        &self,
        polynomial: &Polynomial<F>,
        // Pre allocate space for decomposition
        decompose_space: &mut DecompositionSpace<F>,
        polynomial_space: &mut PolynomialSpace<F>,
        // Output destination
        destination: &mut NTTRLWE<F>,
    ) {
        let coeff_count = polynomial.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();

        polynomial_space.copy_from(polynomial);

        destination.set_zero();

        let mut ntt_polynomial = NTTPolynomial::new(Vec::new());

        self.iter().for_each(|g_rlwe| {
            polynomial_space.decompose_lsb_bits_inplace(self.basis, decompose_space);
            ntt_table.transform_slice(decompose_space.as_mut_slice());

            std::mem::swap(decompose_space.data_mut(), ntt_polynomial.data_mut());
            destination.add_ntt_rlwe_mul_ntt_polynomial_assign_fast(g_rlwe, &ntt_polynomial);
            std::mem::swap(decompose_space.data_mut(), ntt_polynomial.data_mut());
        })
    }

    /// Perform `destination = self + rhs * ntt_polynomial`, and store the result into destination.
    pub fn add_ntt_gadget_rlwe_mul_ntt_polynomial_inplace(
        &self,
        rhs: &Self,
        ntt_polynomial: &NTTPolynomial<F>,
        destination: &mut NTTGadgetRLWE<F>,
    ) {
        destination
            .iter_mut()
            .zip(self.iter())
            .zip(rhs.iter())
            .for_each(|((des, l), r)| {
                l.add_ntt_rlwe_mul_ntt_polynomial_inplace(r, ntt_polynomial, des);
            })
    }
}

impl<F: NTTField> NTTGadgetRLWE<F> {
    /// Generate a `NTTGadgetRLWE<F>` sample which encrypts `0`.
    pub fn generate_random_zero_sample<R>(
        secret_key: &NTTPolynomial<F>,
        basis: Basis<F>,
        error_sampler: FieldDiscreteGaussianSampler,
        mut rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let data = (0..basis.decompose_len())
            .map(|_| <NTTRLWE<F>>::generate_random_zero_sample(secret_key, error_sampler, &mut rng))
            .collect();
        Self { data, basis }
    }

    /// Generate a `NTTGadgetRLWE<F>` sample which encrypts `1`.
    pub fn generate_random_one_sample<R>(
        secret_key: &NTTPolynomial<F>,
        basis: Basis<F>,
        error_sampler: FieldDiscreteGaussianSampler,
        mut rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let len = basis.decompose_len();
        let basis_value = basis.basis();
        let mut basis_power = F::ONE;
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            let r = <NTTRLWE<F>>::generate_random_value_sample(
                secret_key,
                basis_power,
                error_sampler,
                &mut rng,
            );
            data.push(r);
            basis_power = F::new(basis_power.get() * basis_value);
        }

        Self { data, basis }
    }

    /// Generate a `NTTGadgetRLWE<F>` sample which encrypts `-s`.
    pub fn generate_random_neg_secret_sample<R>(
        secret_key: &NTTPolynomial<F>,
        basis: Basis<F>,
        error_sampler: FieldDiscreteGaussianSampler,
        mut rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let len = basis.decompose_len();
        let basis_value = basis.basis();
        let mut basis_power = F::ONE;
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            let mut r =
                <NTTRLWE<F>>::generate_random_zero_sample(secret_key, error_sampler, &mut rng);
            r.a_mut_slice().iter_mut().for_each(|v| *v += basis_power);
            data.push(r);
            basis_power = F::new(basis_power.get() * basis_value);
        }

        Self { data, basis }
    }
}
