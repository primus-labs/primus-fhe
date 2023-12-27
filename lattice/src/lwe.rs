use algebra::{field::NTTField, polynomial::Polynomial, ring::Ring};

use crate::{GadgetRLWE, RLWE};

/// Represents a cryptographic structure based on the Learning with Errors (LWE) problem.
/// The LWE problem is a fundamental component in modern cryptography, often used to build
/// secure cryptographic systems that are considered hard to crack by quantum computers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LWE<R: Ring> {
    /// A vector of elements of `R`, representing the public vector part of the LWE instance.
    a: Vec<R>,
    /// An element of `R`, representing the value which is computed as
    /// the dot product of `a` with a secret vector, plus message and some noise.
    b: R,
}

impl<R: Ring> From<(Vec<R>, R)> for LWE<R> {
    /// Converts a tuple `(a, b)` into an instance of `Self`.
    ///
    /// # Arguments
    ///
    /// * `a` - A vector of type `R`.
    /// * `b` - An instance of type `R`.
    ///
    /// # Returns
    ///
    /// An instance of `Self`.
    #[inline]
    fn from((a, b): (Vec<R>, R)) -> Self {
        Self { a, b }
    }
}

impl<R: Ring> LWE<R> {
    /// Creates a new [`LWE<R>`].
    #[inline]
    pub fn new(a: Vec<R>, b: R) -> Self {
        Self { a, b }
    }

    /// Creates a new [`LWE<R>`] with reference.
    #[inline]
    pub fn from_ref(a: &[R], b: R) -> Self {
        Self { a: a.to_vec(), b }
    }

    /// Returns a reference to the `a` of this [`LWE<R>`].
    #[inline]
    pub fn a(&self) -> &[R] {
        self.a.as_ref()
    }

    /// Returns a mutable reference to the `a` of this [`LWE<R>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut Vec<R> {
        &mut self.a
    }

    /// Returns the `b` of this [`LWE<R>`].
    #[inline]
    pub fn b(&self) -> R {
        self.b
    }

    /// Returns a mutable reference to the `b` of this [`LWE<R>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut R {
        &mut self.b
    }

    /// Perform component-wise addition of two [`LWE<R>`].
    #[inline]
    pub fn add_component_wise(mut self, rhs: &Self) -> Self {
        self.add_inplace_component_wise(rhs);
        self
    }

    /// Perform component-wise subtraction of two [`LWE<R>`].
    #[inline]
    pub fn sub_component_wise(mut self, rhs: &Self) -> Self {
        self.sub_inplace_component_wise(rhs);
        self
    }

    /// Performs an in-place component-wise addition
    /// on the `self` [`LWE<R>`] with another `rhs` [`LWE<R>`].
    #[inline]
    pub fn add_inplace_component_wise(&mut self, rhs: &Self) {
        assert_eq!(self.a().len(), rhs.a().len());
        self.a_mut()
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v0, v1)| *v0 += *v1);
        *self.b_mut() += rhs.b();
    }

    /// Performs an in-place component-wise subtraction
    /// on the `self` [`LWE<R>`] with another `rhs` [`LWE<R>`].
    #[inline]
    pub fn sub_inplace_component_wise(&mut self, rhs: &Self) {
        assert_eq!(self.a().len(), rhs.a().len());
        self.a_mut()
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v0, v1)| *v0 -= *v1);
        *self.b_mut() -= rhs.b();
    }
}

impl<F: NTTField> LWE<F> {
    /// key switch
    pub fn key_switch(&self, ksk: &[GadgetRLWE<F>], nl: usize) -> LWE<F> {
        let a: Vec<Polynomial<F>> = self
            .a
            .chunks_exact(nl)
            .map(|a| {
                <Polynomial<F>>::new(
                    std::iter::once(a[0])
                        .chain(a.iter().skip(1).rev().map(|&x| -x))
                        .collect(),
                )
            })
            .collect();

        let mut init = RLWE::new(
            Polynomial::zero_with_coeff_count(nl),
            Polynomial::zero_with_coeff_count(nl),
        );
        init.b_mut()[0] = self.b;

        ksk.iter()
            .zip(a)
            .fold(init, |acc, (k_i, a_i)| {
                acc.sub_element_wise(&k_i.mul_with_polynomial(&a_i))
            })
            .extract_lwe()
    }

    /// modulus switch
    pub fn modulus_switch<R: Ring>(&self, ql: f64, qr: f64) -> LWE<R> {
        let a: Vec<R> = self
            .a
            .iter()
            .map(|&v| R::from_f64((v.as_f64() * ql / qr).round()))
            .collect();
        let b = R::from_f64((self.b.as_f64() * ql / qr).round());
        <LWE<R>>::new(a, b)
    }
}
