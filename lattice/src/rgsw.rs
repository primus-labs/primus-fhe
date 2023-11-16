use algebra::{field::NTTField, polynomial::NTTPolynomial};

use crate::{GadgetRLWE, RLWE};

/// A generic rgsw struct type.
pub struct RGSW<F: NTTField> {
    c0: GadgetRLWE<F>,
    c1: GadgetRLWE<F>,
}

impl<F: NTTField> RGSW<F> {
    /// Creates a new [`RGSW<F>`].
    #[inline]
    pub fn new(c0: GadgetRLWE<F>, c1: GadgetRLWE<F>) -> Self {
        Self { c0, c1 }
    }

    /// Returns a reference to the `c0` of this [`RGSW<F>`].
    #[inline]
    pub fn c0(&self) -> &GadgetRLWE<F> {
        &self.c0
    }

    /// Returns a reference to the `c1` of this [`RGSW<F>`].
    #[inline]
    pub fn c1(&self) -> &GadgetRLWE<F> {
        &self.c1
    }

    /// Returns a reference to the basis of this [`RGSW<F>`].
    #[inline]
    pub fn basis(&self) -> &F::Modulus {
        self.c0.basis()
    }

    /// Performs a multiplication on the `self` [`RGSW<F>`] with another `rlwe` [`RLWE<F>`],
    /// return a [`RLWE<F>`].
    #[inline]
    pub fn mul_with_rlwe(&self, rlwe: &RLWE<F>) -> RLWE<F> {
        self.c0()
            .mul_with_polynomial(rlwe.a())
            .add_element_wise(&self.c1().mul_with_polynomial(rlwe.b()))
    }

    /// Performs a multiplication on the `self` [`RGSW<F>`] with another `rgsw` [`RGSW<F>`],
    /// return a [`RGSW<F>`].
    #[inline]
    pub fn mul_with_rgsw(&self, rgsw: &RGSW<F>) -> RGSW<F> {
        let basis = self.basis().clone();

        let ntt_c0 = self.c0().to_ntt_poly();
        let ntt_c1 = self.c1().to_ntt_poly();

        let c0_data: Vec<RLWE<F>> = rgsw
            .c0()
            .iter()
            .map(|rlwe| ntt_rgsw_mul_rlwe(&ntt_c0, &ntt_c1, rlwe, basis.clone()))
            .collect();
        let c0 = GadgetRLWE::new(c0_data, basis.clone());

        let c1_data: Vec<RLWE<F>> = rgsw
            .c1()
            .iter()
            .map(|rlwe| ntt_rgsw_mul_rlwe(&ntt_c0, &ntt_c1, rlwe, basis.clone()))
            .collect();
        let c1 = GadgetRLWE::new(c1_data, basis);

        RGSW::new(c0, c1)
    }
}

/// An optimized version `rgsw * rlwe`, the rgsw input is its ntt polynomials.
///
/// This method can decrease the numbers of conversion from [`Polynomial<F>`] to [`NTTPolynomial<F>`].
fn ntt_rgsw_mul_rlwe<F: NTTField>(
    c0: &[(NTTPolynomial<F>, NTTPolynomial<F>)],
    c1: &[(NTTPolynomial<F>, NTTPolynomial<F>)],
    rlwe: &RLWE<F>,
    basis: F::Modulus,
) -> RLWE<F> {
    let decomposed = rlwe.a().decompose(basis.clone());
    let intermediate = match (c0, decomposed.as_slice()) {
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

    let decompose = rlwe.b().decompose(basis.clone());
    c1.iter()
        .zip(decompose)
        .fold(intermediate, |acc, (r, p)| {
            let p = <NTTPolynomial<F>>::from(p);
            (acc.0 + &r.0 * &p, acc.1 + &r.1 * p)
        })
        .into()
}
