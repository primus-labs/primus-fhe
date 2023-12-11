use algebra::{field::Field, ring::Ring};

use crate::KeyGenerator;

/// single parameter
pub struct Param<R: Ring> {
    n: usize,
    err_std_dev: f64,
    key_gen: KeyGenerator<R>,
}

impl<R: Ring> Param<R> {
    /// Creates a new [`Param<R>`].
    pub fn new(n: usize, err_std_dev: f64) -> Self {
        Self {
            n,
            err_std_dev,
            key_gen: KeyGenerator::new(n),
        }
    }

    /// Returns the n of this [`Param<R>`].
    pub fn n(&self) -> usize {
        self.n
    }

    /// Returns a reference to the key gen of this [`Param<R>`].
    pub fn key_gen(&self) -> &KeyGenerator<R> {
        &self.key_gen
    }
}

/// parameters
pub struct Params<R: Ring, F: Field> {
    lwe: Param<R>,
    rlwe: Param<F>,
}

impl<R: Ring, F: Field> Params<R, F> {
    /// Creates a new [`Params`].
    pub fn new(lwe: Param<R>, rlwe: Param<F>) -> Self {
        Self { lwe, rlwe }
    }
}
