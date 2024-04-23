use algebra::transformation::AbstractNTT;
use algebra::{ntt_add_mul_assign, NTTField, NTTPolynomial, Polynomial};

use crate::{DecompositionSpace, NTTGadgetNTRU, NTTNTRUSpace, PolynomialSpace};

/// A cryptographic structure for NTRU.
/// This structure is used in advanced cryptographic systems and protocols, particularly
/// those that require efficient homomorphic encryption properties. It consists of a [`Polynomial<F>`]
/// over a finite field that supports Number Theoretic Transforms (NTT), which is
/// often necessary for efficient polynomial multiplication.
///
/// The [`NTRU`] struct is generic over a type `F` which is bounded by the `NTTField` trait, ensuring
/// that the operations of addition, subtraction, and multiplication are performed in a field suitable
/// for NTT. This is crucial for the security and correctness of cryptographic operations based on NTRU.
///
/// The fields `data` is kept private within the crate to maintain encapsulation and is
/// accessible through public API functions that enforce any necessary invariants.
#[derive(Debug, Clone)]
pub struct NTRU<F: NTTField> {
    data: Polynomial<F>,
}

impl<F: NTTField> NTRU<F> {
    /// Creates a new [`NTRU<F>`].
    #[inline]
    pub fn new(data: Polynomial<F>) -> Self {
        Self { data }
    }

    /// Creates a new [`NTRU<F>`] with reference of [`Polynomial<F>`].
    #[inline]
    pub fn from_ref(data: &Polynomial<F>) -> Self {
        Self { data: data.clone() }
    }

    /// Creates a new [`NTRU<F>`] that is initialized to zero.
    ///
    /// # Arguments
    ///
    /// * `coeff_count` - The number of coefficients in the polynomial.
    ///
    /// # Returns
    ///
    /// A new [`NTRU<F>`] whose polynomial is initialized to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> Self {
        Self {
            data: Polynomial::zero(coeff_count),
        }
    }

    /// Set all entries equal to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.data.set_zero();
    }

    /// Returns a reference to the data of this [`NTRU<F>`].
    #[inline]
    pub fn data(&self) -> &Polynomial<F> {
        &self.data
    }

    /// Returns a mutable reference to the data of this [`NTRU<F>`].
    #[inline]
    pub fn data_mut(&mut self) -> &mut Polynomial<F> {
        &mut self.data
    }

    /// Extracts a slice of `data` of this [`NTRU<F>`].
    #[inline]
    pub fn as_slice(&self) -> &[F] {
        self.data.as_slice()
    }

    /// Extracts a mutable slice of `data` of this [`NTRU<F>`].
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [F] {
        self.data.as_mut_slice()
    }

    /// Perform element-wise addition of two [`NTRU<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `add_element_wise`.
    #[inline]
    pub fn add_element_wise_ref(&self, rhs: &Self) -> Self {
        Self {
            data: self.data() + rhs.data(),
        }
    }

    /// Perform element-wise addition of two [`NTRU<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is not a reference.
    /// If your `self` is a reference, you can use function `add_element_wise_ref`.
    #[inline]
    pub fn add_element_wise(self, rhs: &Self) -> Self {
        Self {
            data: self.data + rhs.data(),
        }
    }

    /// Perform element-wise subtraction of two [`NTRU<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `sub_element_wise`.
    #[inline]
    pub fn sub_element_wise_ref(&self, rhs: &Self) -> Self {
        Self {
            data: self.data() - rhs.data(),
        }
    }

    /// Perform element-wise subtraction of two [`NTRU<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is not a reference.
    /// If your `self` is a reference, you can use function `sub_element_wise_ref`.
    #[inline]
    pub fn sub_element_wise(self, rhs: &Self) -> Self {
        Self {
            data: self.data - rhs.data(),
        }
    }

    /// Performs an in-place element-wise addition
    /// on the `self` [`NTRU<F>`] with another `rhs` [`NTRU<F>`].
    #[inline]
    pub fn add_assign_element_wise(&mut self, rhs: &Self) {
        self.data += rhs.data();
    }

    /// Performs an in-place element-wise subtraction
    /// on the `self` [`NTRU<F>`] with another `rhs` [`NTRU<F>`].
    #[inline]
    pub fn sub_assign_element_wise(&mut self, rhs: &Self) {
        self.data -= rhs.data();
    }

    /// Performs a multiplication on the `self` [`NTRU<F>`] with another `small_ntt_gadget_ntru` [`NTTGadgetNTRU<F>`],
    /// output the [`NTRU<F>`] result into `destination`.
    ///
    /// # Attention
    /// The message of **`small_ntt_gadget_ntru`** is restricted to small messages `m`, typically `m = ±Xⁱ`
    #[inline]
    pub fn mul_small_ntt_gadget_ntru_inplace(
        &self,
        small_ntt_gadget_ntru: &NTTGadgetNTRU<F>,
        // Pre allocate space
        decompose_space: &mut DecompositionSpace<F>,
        polynomial_space: &mut PolynomialSpace<F>,
        median: &mut NTTNTRUSpace<F>,
        // Output destination
        destination: &mut NTRU<F>,
    ) {
        small_ntt_gadget_ntru.mul_ntru_inplace(
            self.data(),
            decompose_space,
            polynomial_space,
            median,
        );

        median.inverse_transform_inplace(destination)
    }
}

/// A cryptographic structure for NTRU.
/// This structure is used in advanced cryptographic systems and protocols, particularly
/// those that require efficient homomorphic encryption properties. It consists of a [`NTTPolynomial<F>`]
/// over a finite field that supports Number Theoretic Transforms (NTT), which is
/// often necessary for efficient polynomial multiplication.
///
/// The [`NTTNTRU`] struct is generic over a type `F` which is bounded by the `NTTField` trait, ensuring
/// that the operations of addition, subtraction, and multiplication are performed in a field suitable
/// for NTT. This is crucial for the security and correctness of cryptographic operations based on RLWE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NTTNTRU<F: NTTField> {
    pub(crate) data: NTTPolynomial<F>,
}

impl<F: NTTField> NTTNTRU<F> {
    /// Creates a new [`NTTNTRU<F>`].
    #[inline]
    pub fn new(data: NTTPolynomial<F>) -> Self {
        Self { data }
    }

    /// Creates a new [`NTTNTRU<F>`] with reference of [`NTTPolynomial<F>`].
    #[inline]
    pub fn from_ref(data: &NTTPolynomial<F>) -> Self {
        Self { data: data.clone() }
    }

    /// Creates a [`NTTNTRU<F>`] with all entries equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> NTTNTRU<F> {
        Self {
            data: <NTTPolynomial<F>>::zero(coeff_count),
        }
    }

    /// Set all entries equal to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.data.set_zero();
    }

    /// Returns a reference to the data of this [`NTTNTRU<F>`].
    #[inline]
    pub fn data(&self) -> &NTTPolynomial<F> {
        self.data.as_ref()
    }

    /// Returns a mutable reference to the data of this [`NTTNTRU<F>`].
    #[inline]
    pub fn data_mut(&mut self) -> &mut NTTPolynomial<F> {
        &mut self.data
    }

    /// Extracts a slice of `data` of this [`NTTNTRU<F>`].
    #[inline]
    pub fn as_slice(&self) -> &[F] {
        self.data.as_slice()
    }

    /// Extracts a mutable slice of `data` of this [`NTTNTRU<F>`].
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [F] {
        self.data.as_mut_slice()
    }

    /// Perform element-wise addition of two [`NTTNTRU<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `add_element_wise`.
    #[inline]
    pub fn add_element_wise_ref(&self, rhs: &Self) -> Self {
        Self {
            data: self.data() + rhs.data(),
        }
    }

    /// Perform element-wise addition of two [`NTTNTRU<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is not a reference.
    /// If your `self` is a reference, you can use function `add_element_wise_ref`.
    #[inline]
    pub fn add_element_wise(self, rhs: &Self) -> Self {
        Self {
            data: self.data + rhs.data(),
        }
    }

    /// Perform element-wise subtraction of two [`NTTNTRU<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `sub_element_wise`.
    #[inline]
    pub fn sub_element_wise_ref(&self, rhs: &Self) -> Self {
        Self {
            data: self.data() - rhs.data(),
        }
    }

    /// Perform element-wise subtraction of two [`NTTNTRU<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is not a reference.
    /// If your `self` is a reference, you can use function `sub_element_wise_ref`.
    #[inline]
    pub fn sub_element_wise(self, rhs: &Self) -> Self {
        Self {
            data: self.data - rhs.data(),
        }
    }

    /// Performs an in-place element-wise addition
    /// on the `self` [`NTTNTRU<F>`] with another `rhs` [`NTTNTRU<F>`].
    #[inline]
    pub fn add_assign_element_wise(&mut self, rhs: &Self) {
        self.data += rhs.data();
    }

    /// Performs an in-place element-wise subtraction
    /// on the `self` [`NTTNTRU<F>`] with another `rhs` [`NTTNTRU<F>`].
    #[inline]
    pub fn sub_assign_element_wise(&mut self, rhs: &Self) {
        self.data -= rhs.data();
    }

    /// ntt inverse transform
    pub fn inverse_transform_inplace(&self, destination: &mut NTRU<F>) {
        let coeff_count = destination.data.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();

        let d = destination.as_mut_slice();

        d.copy_from_slice(self.as_slice());

        ntt_table.inverse_transform_slice(d);
    }

    /// Performs `self = self + ntt_ntru * ntt_polynomial`.
    #[inline]
    pub fn add_ntt_ntru_mul_ntt_polynomial_assign(
        &mut self,
        ntt_ntru: &NTTNTRU<F>,
        ntt_polynomial: &NTTPolynomial<F>,
    ) {
        ntt_add_mul_assign(self.data_mut(), ntt_ntru.data(), ntt_polynomial);
    }
}
