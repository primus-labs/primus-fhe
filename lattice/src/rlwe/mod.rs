use algebra::{
    field::NTTField,
    polynomial::{NTTPolynomial, Polynomial},
};

/// A generic rlwe struct type.
#[derive(Clone)]
pub enum Rlwe<F: NTTField> {
    NativeRlwe {
        a: Polynomial<F>,
        b: Polynomial<F>,
    },
    NTTRlwe {
        a: NTTPolynomial<F>,
        b: NTTPolynomial<F>,
    },
}
