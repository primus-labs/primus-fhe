use algebra::{field::NTTField, polynomial::NTTPolynomial};

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
    pub fn mul_with_rgsw(&self, rhs: &Self) -> Self {
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

        Self::new(c_neg_s_m, c_m)
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
