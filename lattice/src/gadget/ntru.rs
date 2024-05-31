use std::slice::{Iter, IterMut};

use algebra::transformation::AbstractNTT;
use algebra::{Basis, FieldDiscreteGaussianSampler, NTTField, NTTPolynomial, Polynomial};
use rand::{CryptoRng, Rng};

use crate::{ntru::NTRU, DecompositionSpace, PolynomialSpace, NTTNTRU};

/// A representation of NTRU ciphertexts with respect to different powers
/// of a base, used to control noise growth in polynomial multiplications.
///
/// [`GadgetNTRU`] stores a sequence of [`NTRU`] ciphertexts where each [`NTRU<F>`] instance within
/// the `data` vector represents a ciphertext of a scaled version of a message `m` by successive
/// powers of the `basis`. The first element of `data` is the ciphertext of `m`, the second is `basis * m`,
/// the third is `basis^2 * m`, and so on. This is particularly useful in cryptographic operations
/// where reducing the noise growth during the multiplication of NTRU ciphertexts with polynomials is crucial.
///
/// The struct is generic over a type `F` that must implement the [`NTTField`] trait, which ensures that
/// the field operations are compatible with Number Theoretic Transforms, a key requirement for
/// efficient polynomial operations in NTRU-based cryptography.
#[derive(Debug, Clone)]
pub struct GadgetNTRU<F: NTTField> {
    /// A vector of NTRU ciphertexts, each encrypted message with a different power of the `basis`.
    data: Vec<NTRU<F>>,
    /// The base with respect to which the ciphertexts are scaled.
    basis: Basis<F>,
}

impl<F: NTTField> From<NTTGadgetNTRU<F>> for GadgetNTRU<F> {
    #[inline]
    fn from(value: NTTGadgetNTRU<F>) -> Self {
        let NTTGadgetNTRU { data, basis } = value;
        let data = data.into_iter().map(From::from).collect();
        Self { data, basis }
    }
}

impl<F: NTTField> GadgetNTRU<F> {
    /// Creates a new [`GadgetNTRU<F>`].
    #[inline]
    pub fn new(data: Vec<NTRU<F>>, basis: Basis<F>) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_len());
        Self { data, basis }
    }

    /// Creates a new [`GadgetNTRU<F>`] with reference.
    #[inline]
    pub fn from_ref(data: &[NTRU<F>], basis: Basis<F>) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_len());
        Self {
            data: data.to_vec(),
            basis,
        }
    }

    /// Creates a [`GadgetNTRU<F>`] with all entries equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize, basis: Basis<F>) -> Self {
        Self {
            data: (0..basis.decompose_len())
                .map(|_| NTRU::zero(coeff_count))
                .collect(),
            basis,
        }
    }

    /// Set all entries equal to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.data.iter_mut().for_each(|ntru| ntru.set_zero());
    }

    /// Returns a reference to the `data` of this [`GadgetNTRU<F>`].
    #[inline]
    pub fn data(&self) -> &[NTRU<F>] {
        &self.data
    }

    /// Returns the basis of this [`GadgetNTRU<F>`].
    #[inline]
    pub fn basis(&self) -> Basis<F> {
        self.basis
    }

    /// Returns an iterator over the `data` of this [`GadgetNTRU<F>`].
    #[inline]
    pub fn iter(&self) -> Iter<'_, NTRU<F>> {
        self.data.iter()
    }

    /// Returns an iterator over the `data` of this [`GadgetNTRU<F>`]
    /// that allows modifying each value.
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, NTRU<F>> {
        self.data.iter_mut()
    }
}

/// A representation of NTRU ciphertexts with respect to different powers
/// of a base, used to control noise growth in polynomial multiplications.
///
/// [`NTTGadgetNTRU`] stores a sequence of [`NTTNTRU`] ciphertexts where each [`NTTNTRU<F>`] instance within
/// the `data` vector represents a ciphertext of a scaled version of a message `m` by successive
/// powers of the `basis`. The first element of `data` is the ciphertext of `m`, the second is `basis * m`,
/// the third is `basis^2 * m`, and so on. This is particularly useful in cryptographic operations
/// where reducing the noise growth during the multiplication of RLWE ciphertexts with polynomials is crucial.
///
/// The struct is generic over a type `F` that must implement the [`NTTField`] trait, which ensures that
/// the field operations are compatible with Number Theoretic Transforms, a key requirement for
/// efficient polynomial operations in RLWE-based cryptography.
#[derive(Debug, Clone)]
pub struct NTTGadgetNTRU<F: NTTField> {
    /// A vector of NTT NTRU ciphertexts, each encrypted message with a different power of the `basis`.
    data: Vec<NTTNTRU<F>>,
    /// The base with respect to which the ciphertexts are scaled.
    basis: Basis<F>,
}

impl<F: NTTField> From<GadgetNTRU<F>> for NTTGadgetNTRU<F> {
    #[inline]
    fn from(value: GadgetNTRU<F>) -> Self {
        let GadgetNTRU { data, basis } = value;
        let data = data.into_iter().map(From::from).collect();
        Self { data, basis }
    }
}

impl<F: NTTField> NTTGadgetNTRU<F> {
    /// Creates a new [`NTTGadgetNTRU<F>`].
    #[inline]
    pub fn new(data: Vec<NTTNTRU<F>>, basis: Basis<F>) -> Self {
        Self { data, basis }
    }

    /// Creates a new [`NTTGadgetNTRU<F>`] with reference.
    #[inline]
    pub fn from_ref(data: &[NTTNTRU<F>], basis: Basis<F>) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_len());
        Self {
            data: data.to_vec(),
            basis,
        }
    }

    /// Creates a [`NTTGadgetNTRU<F>`] with all entries equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize, basis: Basis<F>) -> Self {
        Self {
            data: (0..basis.decompose_len())
                .map(|_| NTTNTRU::zero(coeff_count))
                .collect(),
            basis,
        }
    }

    /// Set all entries equal to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.data.iter_mut().for_each(|ntru| ntru.set_zero());
    }

    /// Returns a reference to the `data` of this [`NTTGadgetNTRU<F>`].
    #[inline]
    pub fn data(&self) -> &[NTTNTRU<F>] {
        &self.data
    }

    /// Returns the basis of this [`NTTGadgetNTRU<F>`].
    #[inline]
    pub fn basis(&self) -> Basis<F> {
        self.basis
    }

    /// Returns an iterator over the `data` of this [`NTTGadgetNTRU<F>`].
    #[inline]
    pub fn iter(&self) -> Iter<'_, NTTNTRU<F>> {
        self.data.iter()
    }

    /// Returns an iterator over the `data` of this [`NTTGadgetNTRU<F>`]
    /// that allows modifying each value.
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, NTTNTRU<F>> {
        self.data.iter_mut()
    }

    /// Perform multiplication between [`NTTGadgetNTRU<F>`] and [`Polynomial<F>`],
    /// stores the result into `destination`.
    pub fn mul_ntru_inplace(
        &self,
        ntru: &Polynomial<F>,
        // Pre allocate space for decomposition
        decompose_space: &mut DecompositionSpace<F>,
        polynomial_space: &mut PolynomialSpace<F>,
        // Output destination
        destination: &mut NTTNTRU<F>,
    ) {
        let coeff_count = ntru.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();

        polynomial_space.copy_from(ntru);

        destination.set_zero();

        self.iter().for_each(|g_ntru| {
            polynomial_space.decompose_lsb_bits_inplace(self.basis, decompose_space.as_mut_slice());
            ntt_table.transform_slice(decompose_space.as_mut_slice());
            destination.add_ntt_ntru_mul_ntt_polynomial_assign(g_ntru, decompose_space);
        })
    }

    /// Perform `self + rhs * ntt_polynomial`, and store the result into destination.
    pub fn add_ntt_gadget_ntru_mul_ntt_polynomial_inplace(
        &self,
        rhs: &Self,
        ntt_polynomial: &NTTPolynomial<F>,
        destination: &mut Self,
    ) {
        destination
            .iter_mut()
            .zip(self.iter())
            .zip(rhs.iter())
            .for_each(|((des, l), r)| {
                l.add_ntt_ntru_mul_ntt_polynomial_inplace(r, ntt_polynomial, des);
            })
    }

    /// Generate a `NTTGadgetNTRU<F>` sample which encrypts `0`.
    pub fn generate_random_zero_sample<R>(
        inv_secret_key: &NTTPolynomial<F>,
        basis: Basis<F>,
        error_sampler: FieldDiscreteGaussianSampler,
        mut rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let data = (0..basis.decompose_len())
            .map(|_| {
                <NTTNTRU<F>>::generate_random_zero_sample(inv_secret_key, error_sampler, &mut rng)
            })
            .collect();
        Self { data, basis }
    }

    /// Generate a `NTTGadgetNTRU<F>` sample which encrypts `1`.
    pub fn generate_random_one_sample<R>(
        inv_secret_key: &NTTPolynomial<F>,
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
        for _ in 0..(len - 1) {
            let r = <NTTNTRU<F>>::generate_random_value_sample(
                inv_secret_key,
                basis_power,
                error_sampler,
                &mut rng,
            );
            data.push(r);
            basis_power = F::new(basis_power.get() * basis_value);
        }

        let r = <NTTNTRU<F>>::generate_random_value_sample(
            inv_secret_key,
            basis_power,
            error_sampler,
            &mut rng,
        );
        data.push(r);

        Self { data, basis }
    }
}
