use std::slice::{Iter, IterMut};

use algebra::{transformation::AbstractNTT, Basis, NTTField, Polynomial};

use crate::{DecomposeSpace, PolynomialSpace, NTTRLWE, RLWE};

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

        let mut decompose_space = DecomposeSpace::new(coeff_count);
        let mut polynomial = polynomial.clone();

        let mut ntt_rlwe = <NTTRLWE<F>>::zero(coeff_count);
        let mut temp = <NTTRLWE<F>>::zero(coeff_count);

        let space = decompose_space.get_mut();
        self.iter().for_each(|g| {
            polynomial.decompose_lsb_bits_inplace(self.basis, space);
            g.mul_polynomial_inplace_lazy(space, &mut temp);
            ntt_rlwe.add_element_wise_assign(&temp);
        });
        <RLWE<F>>::from(ntt_rlwe)
    }

    /// Perform multiplication between [`GadgetRLWE<F>`] and [`Polynomial<F>`],
    /// then add the `rlwe`, return a [`RLWE<F>`].
    #[inline]
    pub fn mul_polynomial_add_rlwe(&self, polynomial: &Polynomial<F>, rlwe: RLWE<F>) -> RLWE<F> {
        let coeff_count = polynomial.coeff_count();

        let mut decompose_space = DecomposeSpace::new(coeff_count);
        let mut polynomial = polynomial.clone();

        let mut ntt_rlwe = <NTTRLWE<F>>::from(rlwe);
        let mut temp = <NTTRLWE<F>>::zero(coeff_count);

        let space = decompose_space.get_mut();
        self.iter().for_each(|g| {
            polynomial.decompose_lsb_bits_inplace(self.basis, space);
            g.mul_polynomial_inplace_lazy(space, &mut temp);
            ntt_rlwe.add_element_wise_assign(&temp);
        });
        <RLWE<F>>::from(ntt_rlwe)
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
    #[inline]
    pub fn mul_polynomial(&self, polynomial: &Polynomial<F>) -> NTTRLWE<F> {
        let coeff_count = polynomial.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();

        let mut decompose_space = DecomposeSpace::new(coeff_count);
        let mut polynomial = polynomial.clone();

        let mut ntt_rlwe = <NTTRLWE<F>>::zero(coeff_count);

        let space = decompose_space.get_mut();
        self.iter().for_each(|g| {
            polynomial.decompose_lsb_bits_inplace(self.basis, space);
            ntt_table.transform_slice(space.as_mut_slice());
            ntt_rlwe.add_ntt_rlwe_mul_ntt_polynomial_inplace(g, space.as_mut_slice());
        });

        ntt_rlwe
    }

    /// Perform multiplication between [`NTTGadgetRLWE<F>`] and [`Polynomial<F>`],
    /// stores the result into `destination`.
    #[inline]
    pub fn mul_polynomial_inplace(
        &self,
        polynomial: &Polynomial<F>,
        // Pre allocate space for decomposition
        decompose_space: &mut DecomposeSpace<F>,
        polynomial_space: &mut PolynomialSpace<F>,
        // Output destination
        destination: &mut NTTRLWE<F>,
    ) {
        let coeff_count = polynomial.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();

        polynomial_space
            .as_mut_slice()
            .copy_from_slice(polynomial.as_slice());

        destination.set_zero();

        self.iter().for_each(|g_rlwe| {
            polynomial_space.decompose_lsb_bits_inplace(self.basis, decompose_space);
            ntt_table.transform_slice(decompose_space.as_mut_slice());
            destination
                .add_ntt_rlwe_mul_ntt_polynomial_inplace(g_rlwe, decompose_space.as_mut_slice());
        })
    }
}
