use std::ops::Mul;

use algebra::{
    field::NTTField,
    polynomial::{NTTPolynomial, Polynomial},
};

use crate::Rlwe;

#[derive(Clone)]
pub struct GadgetRlwe<F: NTTField> {
    data: Vec<Rlwe<F>>,
    basis: F::Modulus,
}

impl<F: NTTField> GadgetRlwe<F> {
    /// Creates a new [`GadgetRlwe<F>`].
    pub fn new(data: Vec<Rlwe<F>>, basis: F::Modulus) -> Self {
        Self { data, basis }
    }

    /// Returns a reference to the data of this [`GadgetRlwe<F>`].
    pub fn data(&self) -> &[Rlwe<F>] {
        self.data.as_ref()
    }
}

// impl<F: NTTField> Mul<Polynomial<F>> for GadgetRlwe<F> {
//     type Output = Rlwe<F>;

//     fn mul(self, rhs: Polynomial<F>) -> Self::Output {
//         let decompose = rhs.decompose(self.basis);
//         self.data.iter().zip(decompose).fold(init, f)
//     }
// }
