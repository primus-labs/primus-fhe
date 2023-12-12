use algebra::{field::Field, ring::Ring};

use crate::KeyGenerator;

/// single parameter
#[derive(Debug, Clone)]
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

    /// Returns the error standard deviation of this [`Param<R>`].
    pub fn err_std_dev(&self) -> f64 {
        self.err_std_dev
    }
}

/// parameters
#[derive(Debug, Clone)]
pub struct Params<R: Ring, F: Field> {
    lwe: Param<R>,
    rlwe: Param<F>,
}

impl<R: Ring, F: Field> Params<R, F> {
    /// Creates a new [`Params`].
    #[inline]
    pub fn new(lwe: Param<R>, rlwe: Param<F>) -> Self {
        Self { lwe, rlwe }
    }

    /// Returns a reference to the lwe of this [`Params<R, F>`].
    #[inline]
    pub fn lwe(&self) -> &Param<R> {
        &self.lwe
    }

    /// Returns a reference to the rlwe of this [`Params<R, F>`].
    #[inline]
    pub fn rlwe(&self) -> &Param<F> {
        &self.rlwe
    }
}
