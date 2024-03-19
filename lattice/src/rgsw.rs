use algebra::{Basis, NTTField, NTTPolynomial};

use crate::{GadgetRLWE, NTTGadgetRLWE, RLWE};

/// Represents a ciphertext in the Ring-GSW (Ring Learning With Errors) homomorphic encryption scheme.
///
/// The [`RGSW`] struct holds two components, `c_m` and `c_neg_s_m`, each of type [`GadgetRLWE`]. These components are
/// integral to the RGSW encryption scheme, which is a variant of GSW encryption that operates over polynomial
/// rings for efficiency. This scheme is often used in lattice-based cryptography for constructing fully
/// homomorphic encryption systems.
///
/// The [`GadgetRLWE`] structures `c_m` and `c_neg_s_m` contain encrypted data that, when used together, allow for the
/// encrypted computation of linear and non-linear operations on ciphertexts without decrypting them.
/// These gadget representations play a crucial role in performing homomorphic operations by controlling noise
/// growth and enabling efficient arithmetic on encrypted data.
///
/// The struct is generic over a type `F` that must implement the [`NTTField`] trait, indicating that field
/// operations are compatible with Number Theoretic Transforms. This is essential for the efficient polynomial
/// arithmetic required by the encryption scheme.
#[derive(Debug, Clone)]
pub struct RGSW<F: NTTField> {
    /// The first part of the RGSW ciphertext, which is often used for homomorphic operations
    /// and can represent the encrypted data multiplied by some secret value.
    c_neg_s_m: GadgetRLWE<F>,
    /// The second part of the RGSW ciphertext, typically representing the encrypted data.
    c_m: GadgetRLWE<F>,
}

impl<F: NTTField> From<(GadgetRLWE<F>, GadgetRLWE<F>)> for RGSW<F> {
    /// Converts a tuple of `GadgetRLWE` into an instance of `Self`.
    ///
    /// # Arguments
    ///
    /// * `c_neg_s_m` - The first `GadgetRLWE` sample.
    /// * `c_m` - The second `GadgetRLWE` sample.
    ///
    /// # Returns
    ///
    /// An instance of `Self` containing the converted polynomials.
    fn from((c_neg_s_m, c_m): (GadgetRLWE<F>, GadgetRLWE<F>)) -> Self {
        Self { c_neg_s_m, c_m }
    }
}

impl<F: NTTField> RGSW<F> {
    /// Creates a new [`RGSW<F>`].
    #[inline]
    pub fn new(c_neg_s_m: GadgetRLWE<F>, c_m: GadgetRLWE<F>) -> Self {
        Self { c_neg_s_m, c_m }
    }

    /// Creates a new [`RGSW<F>`] with reference.
    #[inline]
    pub fn from_ref(c_neg_s_m: &GadgetRLWE<F>, c_m: &GadgetRLWE<F>) -> Self {
        Self {
            c_neg_s_m: c_neg_s_m.clone(),
            c_m: c_m.clone(),
        }
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

    /// Returns a mutable reference to the c neg s m of this [`RGSW<F>`].
    #[inline]
    pub fn c_neg_s_m_mut(&mut self) -> &mut GadgetRLWE<F> {
        &mut self.c_neg_s_m
    }

    /// Returns a mutable reference to the c m of this [`RGSW<F>`].
    #[inline]
    pub fn c_m_mut(&mut self) -> &mut GadgetRLWE<F> {
        &mut self.c_m
    }

    /// Returns a reference to the basis of this [`RGSW<F>`].
    #[inline]
    pub fn basis(&self) -> Basis<F> {
        self.c_neg_s_m.basis()
    }

    /// Performs a multiplication on the `self` [`RGSW<F>`] with another `small_rgsw` [`RGSW<F>`],
    /// return a [`RGSW<F>`].
    ///
    /// # Attention
    /// The message of **`small_rgsw`** is restricted to small messages `m`, typically `m = ±Xⁱ`
    #[inline]
    pub fn mul_small_rgsw(&self, small_rgsw: &Self) -> Self {
        let small_ntt_rgsw = <NTTRGSW<F>>::from(small_rgsw.clone());
        self.mul_small_ntt_rgsw(&small_ntt_rgsw)
    }

    /// Performs a multiplication on the `self` [`RGSW<F>`] with another `small_ntt_rgsw` [`NTTRGSW<F>`],
    /// return a [`RGSW<F>`].
    ///
    /// # Attention
    /// The message of **`small_ntt_rgsw`** is restricted to small messages `m`, typically `m = ±Xⁱ`
    pub fn mul_small_ntt_rgsw(&self, small_ntt_rgsw: &NTTRGSW<F>) -> Self {
        let basis = self.basis();

        let c0_data: Vec<RLWE<F>> = self
            .c_neg_s_m()
            .iter()
            .map(|rlwe| rlwe.mul_small_ntt_rgsw(small_ntt_rgsw))
            .collect();
        let c_neg_s_m = GadgetRLWE::new(c0_data, basis);

        let c1_data: Vec<RLWE<F>> = self
            .c_m()
            .iter()
            .map(|rlwe| rlwe.mul_small_ntt_rgsw(small_ntt_rgsw))
            .collect();
        let c_m = GadgetRLWE::new(c1_data, basis);

        Self::new(c_neg_s_m, c_m)
    }
}

/// Represents a ciphertext in the Ring-GSW (Ring Learning With Errors) homomorphic encryption scheme.
///
/// The [`NTTRGSW`] struct holds two components, `c_m` and `c_neg_s_m`, each of type [`NTTGadgetRLWE`]. These components are
/// integral to the RGSW encryption scheme, which is a variant of GSW encryption that operates over polynomial
/// rings for efficiency. This scheme is often used in lattice-based cryptography for constructing fully
/// homomorphic encryption systems.
///
/// The [`NTTGadgetRLWE`] structures `c_m` and `c_neg_s_m` contain encrypted data that, when used together, allow for the
/// encrypted computation of linear and non-linear operations on ciphertexts without decrypting them.
/// These gadget representations play a crucial role in performing homomorphic operations by controlling noise
/// growth and enabling efficient arithmetic on encrypted data.
///
/// The struct is generic over a type `F` that must implement the [`NTTField`] trait, indicating that field
/// operations are compatible with Number Theoretic Transforms. This is essential for the efficient polynomial
/// arithmetic required by the encryption scheme.
#[derive(Debug, Clone)]
pub struct NTTRGSW<F: NTTField> {
    /// The first part of the NTT RGSW ciphertext, which is often used for homomorphic operations
    /// and can represent the encrypted data multiplied by some secret value.
    c_neg_s_m: NTTGadgetRLWE<F>,
    /// The second part of the NTT RGSW ciphertext, typically representing the encrypted data.
    c_m: NTTGadgetRLWE<F>,
}

impl<F: NTTField> From<RGSW<F>> for NTTRGSW<F> {
    #[inline]
    fn from(r: RGSW<F>) -> Self {
        Self {
            c_neg_s_m: <NTTGadgetRLWE<F>>::from(r.c_neg_s_m),
            c_m: <NTTGadgetRLWE<F>>::from(r.c_m),
        }
    }
}

impl<F: NTTField> NTTRGSW<F> {
    /// Creates a new [`NTTRGSW<F>`].
    #[inline]
    pub fn new(c_neg_s_m: NTTGadgetRLWE<F>, c_m: NTTGadgetRLWE<F>) -> Self {
        Self { c_neg_s_m, c_m }
    }

    /// Creates a new [`NTTRGSW<F>`] with reference.
    #[inline]
    pub fn from_ref(c_neg_s_m: &NTTGadgetRLWE<F>, c_m: &NTTGadgetRLWE<F>) -> Self {
        Self {
            c_neg_s_m: c_neg_s_m.clone(),
            c_m: c_m.clone(),
        }
    }

    /// Creates a [`NTTRGSW<F>`] with all entries equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize, basis: Basis<F>) -> Self {
        Self {
            c_neg_s_m: NTTGadgetRLWE::zero(coeff_count, basis),
            c_m: NTTGadgetRLWE::zero(coeff_count, basis),
        }
    }

    /// Set all entries equal to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.c_m.set_zero();
        self.c_neg_s_m.set_zero();
    }

    /// Returns a reference to the c neg s m of this [`NTTRGSW<F>`].
    #[inline]
    pub fn c_neg_s_m(&self) -> &NTTGadgetRLWE<F> {
        &self.c_neg_s_m
    }

    /// Returns a reference to the c m of this [`NTTRGSW<F>`].
    #[inline]
    pub fn c_m(&self) -> &NTTGadgetRLWE<F> {
        &self.c_m
    }

    /// Returns a mutable reference to the c neg s m of this [`NTTRGSW<F>`].
    #[inline]
    pub fn c_neg_s_m_mut(&mut self) -> &mut NTTGadgetRLWE<F> {
        &mut self.c_neg_s_m
    }

    /// Returns a mutable reference to the c m of this [`NTTRGSW<F>`].
    #[inline]
    pub fn c_m_mut(&mut self) -> &mut NTTGadgetRLWE<F> {
        &mut self.c_m
    }

    /// Returns a reference to the basis of this [`NTTRGSW<F>`].
    #[inline]
    pub fn basis(&self) -> Basis<F> {
        self.c_neg_s_m.basis()
    }

    /// .
    pub fn mul_ntt_polynomial_assign(&mut self, ntt_polynomial: &NTTPolynomial<F>) {
        self.c_m_mut()
            .iter_mut()
            .for_each(|p| p.mul_ntt_polynomial_assign(ntt_polynomial));
        self.c_neg_s_m_mut()
            .iter_mut()
            .for_each(|p| p.mul_ntt_polynomial_assign(ntt_polynomial));
    }

    /// Perform `self + rhs * ntt_polynomial`, and store the result into destination.
    pub fn add_ntt_rgsw_mul_ntt_polynomial_inplace(
        &self,
        rhs: &Self,
        ntt_polynomial: &NTTPolynomial<F>,
        destination: &mut Self,
    ) {
        self.c_neg_s_m()
            .add_ntt_gadget_rlwe_mul_ntt_polynomial_inplace(
                rhs.c_neg_s_m(),
                ntt_polynomial,
                destination.c_neg_s_m_mut(),
            );
        self.c_m().add_ntt_gadget_rlwe_mul_ntt_polynomial_inplace(
            rhs.c_m(),
            ntt_polynomial,
            destination.c_m_mut(),
        );
    }
}
