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
    #[inline]
    pub fn mul_with_rlwe(&self, rlwe: &RLWE<F>) -> RLWE<F> {
        self.c_neg_s_m()
            .mul_with_polynomial(rlwe.a())
            .add_element_wise(&self.c_m().mul_with_polynomial(rlwe.b()))
    }

    /// Performs a multiplication on the `self` [`RGSW<F>`] with another `rgsw` [`RGSW<F>`],
    /// return a [`RGSW<F>`].
    #[inline]
    pub fn mul_with_rgsw(&self, rgsw: &RGSW<F>) -> RGSW<F> {
        let basis = self.basis();

        let ntt_c_neg_s_m = self.c_neg_s_m().to_ntt_poly();
        let ntt_c_m = self.c_m().to_ntt_poly();

        let c0_data: Vec<RLWE<F>> = rgsw
            .c_neg_s_m()
            .iter()
            .map(|rlwe| ntt_rgsw_mul_rlwe(&ntt_c_neg_s_m, &ntt_c_m, rlwe, basis))
            .collect();
        let c_neg_s_m = GadgetRLWE::new(c0_data, basis);

        let c1_data: Vec<RLWE<F>> = rgsw
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
    let intermediate = match (ntt_c_neg_s_m, decomposed.as_slice()) {
        ([first_rlwe, other_rlwes @ ..], [first_poly, other_polys @ ..]) => {
            let init = (&first_rlwe.0 * first_poly, &first_rlwe.1 * first_poly);
            other_rlwes
                .iter()
                .zip(other_polys)
                .fold(init, |acc, (r, p)| {
                    let p = <NTTPolynomial<F>>::from(p);
                    (acc.0 + &r.0 * &p, acc.1 + &r.1 * p)
                })
        }
        _ => unreachable!(),
    };

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
