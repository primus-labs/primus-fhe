use algebra::{field::Field, ring::Ring};

use crate::Params;

/// fhe scheme
pub struct Vfhe<R: Ring, F: Field> {
    params: Params<R, F>,
}

impl<R: Ring, F: Field> Vfhe<R, F> {
    /// Creates a new [`Vfhe<R, F>`].
    pub fn new(params: Params<R, F>) -> Self {
        Self { params }
    }
}
