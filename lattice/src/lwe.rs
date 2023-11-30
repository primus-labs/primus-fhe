use algebra::ring::Ring;

/// Represents a cryptographic structure based on the Learning with Errors (LWE) problem.
/// The LWE problem is a fundamental component in modern cryptography, often used to build
/// secure cryptographic systems that are considered hard to crack by quantum computers.
///
/// This structure contains two main components:
/// - `a`: A vector of elements of `R`, representing the public vector part of the LWE instance.
/// - `b`: An element of `R`, representing the response value which is computed as
///        the dot product of `a` with a secret vector, plus some noise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LWE<R: Ring> {
    a: Vec<R>,
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
