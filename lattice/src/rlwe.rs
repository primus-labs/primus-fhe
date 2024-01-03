use algebra::{NTTField, NTTPolynomial, Polynomial, Ring};

use crate::LWE;

/// A cryptographic structure for Ring Learning with Errors (RLWE).
/// This structure is used in advanced cryptographic systems and protocols, particularly
/// those that require efficient homomorphic encryption properties. It consists of two [`Polynomial<F>`]
/// `a` and `b` over a finite field that supports Number Theoretic Transforms (NTT), which is
/// often necessary for efficient polynomial multiplication.
///
/// The [`RLWE`] struct is generic over a type `F` which is bounded by the `NTTField` trait, ensuring
/// that the operations of addition, subtraction, and multiplication are performed in a field suitable
/// for NTT. This is crucial for the security and correctness of cryptographic operations based on RLWE.
///
/// The fields `a` and `b` are kept private within the crate to maintain encapsulation and are
/// accessible through public API functions that enforce any necessary invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RLWE<F: NTTField> {
    /// Represents the first component in the RLWE structure.
    /// It is a polynomial where the coefficients are elements of the field `F`.
    pub(crate) a: Polynomial<F>,
    /// Represents the second component in the RLWE structure.
    /// It's also a polynomial with coefficients in the field `F`.
    pub(crate) b: Polynomial<F>,
}

impl<F: NTTField> From<(Polynomial<F>, Polynomial<F>)> for RLWE<F> {
    /// Converts a tuple of polynomials into an instance of `Self`.
    ///
    /// # Arguments
    ///
    /// * `a` - The first polynomial.
    /// * `b` - The second polynomial.
    ///
    /// # Returns
    ///
    /// An instance of [`RLWE<F>`].
    #[inline]
    fn from((a, b): (Polynomial<F>, Polynomial<F>)) -> Self {
        Self { a, b }
    }
}

impl<F: NTTField> From<(NTTPolynomial<F>, NTTPolynomial<F>)> for RLWE<F> {
    /// Converts a tuple of `NTTPolynomials` into an instance of Self.
    ///
    /// # Arguments
    ///
    /// * `a` - The first `NTTPolynomial`.
    /// * `b` - The second `NTTPolynomial`.
    ///
    /// # Returns
    ///
    /// An instance of `Self` containing the converted polynomials.
    #[inline]
    fn from((a, b): (NTTPolynomial<F>, NTTPolynomial<F>)) -> Self {
        Self {
            a: <Polynomial<F>>::from(a),
            b: <Polynomial<F>>::from(b),
        }
    }
}

impl<F: NTTField> Default for RLWE<F> {
    fn default() -> Self {
        Self {
            a: Polynomial::new(Vec::new()),
            b: Polynomial::new(Vec::new()),
        }
    }
}

impl<F: NTTField> RLWE<F> {
    /// Creates a new [`RLWE<F>`].
    #[inline]
    pub fn new(a: Polynomial<F>, b: Polynomial<F>) -> Self {
        Self { a, b }
    }

    /// Creates a new [`RLWE<F>`] with reference of [`Polynomial<F>`].
    #[inline]
    pub fn from_ref(a: &Polynomial<F>, b: &Polynomial<F>) -> Self {
        Self {
            a: a.clone(),
            b: b.clone(),
        }
    }

    /// Creates a new [`RLWE<F>`] that is initialized to zero.
    ///
    /// The `coeff_count` parameter specifies the number of coefficients in the polynomial.
    /// Both `a` and `b` polynomials of the `RLWE<F>` are initialized with zero coefficients.
    ///
    /// # Arguments
    ///
    /// * `coeff_count` - The number of coefficients in the polynomial.
    ///
    /// # Returns
    ///
    /// A new `RLWE<F>` where both `a` and `b` polynomials are initialized to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> Self {
        Self {
            a: Polynomial::zero_with_coeff_count(coeff_count),
            b: Polynomial::zero_with_coeff_count(coeff_count),
        }
    }

    /// Returns a reference to the `a` of this [`RLWE<F>`].
    #[inline]
    pub fn a(&self) -> &Polynomial<F> {
        self.a.as_ref()
    }

    /// Returns a mutable reference to the `a` of this [`RLWE<F>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut Polynomial<F> {
        &mut self.a
    }

    /// Returns a reference to the `b` of this [`RLWE<F>`].
    #[inline]
    pub fn b(&self) -> &Polynomial<F> {
        self.b.as_ref()
    }

    /// Returns a mutable reference to the `b` of this [`RLWE<F>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut Polynomial<F> {
        &mut self.b
    }

    /// Perform element-wise addition of two [`RLWE<F>`].
    #[inline]
    pub fn add_element_wise(self, rhs: &Self) -> Self {
        Self {
            a: self.a + rhs.a(),
            b: self.b + rhs.b(),
        }
    }

    /// Perform element-wise subtraction of two [`RLWE<F>`].
    #[inline]
    pub fn sub_element_wise(self, rhs: &Self) -> Self {
        Self {
            a: self.a - rhs.a(),
            b: self.b - rhs.b(),
        }
    }

    /// Performs an in-place element-wise addition
    /// on the `self` [`RLWE<F>`] with another `rhs` [`RLWE<F>`].
    #[inline]
    pub fn add_inplace_element_wise(&mut self, rhs: &Self) {
        *self.a_mut() += rhs.a();
        *self.b_mut() += rhs.b();
    }

    /// Performs an in-place element-wise subtraction
    /// on the `self` [`RLWE<F>`] with another `rhs` [`RLWE<F>`].
    #[inline]
    pub fn sub_inplace_element_wise(&mut self, rhs: &Self) {
        *self.a_mut() -= rhs.a();
        *self.b_mut() -= rhs.b();
    }

    /// Performs a multiplication on the `self` [`RLWE<F>`] with another `poly` [`Polynomial<F>`],
    /// return a [`RLWE<F>`].
    #[inline]
    pub fn mul_with_polynomial(self, poly: &Polynomial<F>) -> Self {
        let ntt_poly = &<NTTPolynomial<F>>::from(poly);
        Self {
            a: self.a * ntt_poly,
            b: self.b * ntt_poly,
        }
    }

    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_lwe(&self) -> LWE<F> {
        let a = std::iter::once(self.a()[0])
            .chain(self.a().iter().skip(1).rev().map(|&x| -x))
            .collect();
        let b = self.b()[0];

        LWE::<F>::from((a, b))
    }

    /// Perform [`RLWE<F>`] multiply with `Y^r` for functional bootstrapping where `Y = X^(2N/q)`.
    pub fn mul_with_monic_monomial<R: Ring>(&self, nr: usize, nr2dql: usize, r: R) -> Self {
        let r = r.cast_into_usize() * nr2dql;
        if r <= nr {
            #[inline]
            fn rotate<F: NTTField>(p: &Polynomial<F>, n_sub_r: usize) -> Polynomial<F> {
                p[n_sub_r..]
                    .iter()
                    .map(|&v| -v)
                    .chain(p[0..n_sub_r].iter().copied())
                    .collect::<Vec<F>>()
                    .into()
            }
            let n_sub_r = nr - r;
            Self {
                a: rotate(self.a(), n_sub_r),
                b: rotate(self.b(), n_sub_r),
            }
        } else {
            #[inline]
            fn rotate<F: NTTField>(p: &Polynomial<F>, n_mul_2_sub_r: usize) -> Polynomial<F> {
                p[n_mul_2_sub_r..]
                    .iter()
                    .copied()
                    .chain(p[0..n_mul_2_sub_r].iter().map(|&v| -v))
                    .collect::<Vec<F>>()
                    .into()
            }
            let n_mul_2_sub_r = nr - (r - nr);
            Self {
                a: rotate(self.a(), n_mul_2_sub_r),
                b: rotate(self.b(), n_mul_2_sub_r),
            }
        }
    }

    /// Perform [`RLWE<F>`] multiply with `Y^r - 1` for functional bootstrapping where `Y = X^(2N/q)`.
    pub fn mul_with_monic_monomial_sub1<R: Ring>(&self, nr: usize, nr2dql: usize, r: R) -> Self {
        let r = r.cast_into_usize() * nr2dql;
        if r <= nr {
            #[inline]
            fn rotate<F: NTTField>(p: &Polynomial<F>, n_sub_r: usize) -> Polynomial<F> {
                p[n_sub_r..]
                    .iter()
                    .map(|&v| -v)
                    .chain(p[0..n_sub_r].iter().copied())
                    .zip(p.iter())
                    .map(|(v0, v1)| v0 - v1)
                    .collect::<Vec<F>>()
                    .into()
            }
            let n_sub_r = nr - r;
            Self {
                a: rotate(self.a(), n_sub_r),
                b: rotate(self.b(), n_sub_r),
            }
        } else {
            #[inline]
            fn rotate<F: NTTField>(p: &Polynomial<F>, n_mul_2_sub_r: usize) -> Polynomial<F> {
                p[n_mul_2_sub_r..]
                    .iter()
                    .copied()
                    .chain(p[0..n_mul_2_sub_r].iter().map(|&v| -v))
                    .zip(p.iter())
                    .map(|(v0, v1)| v0 - v1)
                    .collect::<Vec<F>>()
                    .into()
            }
            let n_mul_2_sub_r = nr - (r - nr);
            Self {
                a: rotate(self.a(), n_mul_2_sub_r),
                b: rotate(self.b(), n_mul_2_sub_r),
            }
        }
    }
}

/// A cryptographic structure for Ring Learning with Errors (RLWE).
/// This structure is used in advanced cryptographic systems and protocols, particularly
/// those that require efficient homomorphic encryption properties. It consists of two [`NTTPolynomial<F>`]
/// `a` and `b` over a finite field that supports Number Theoretic Transforms (NTT), which is
/// often necessary for efficient polynomial multiplication.
///
/// The [`NTTRLWE`] struct is generic over a type `F` which is bounded by the `NTTField` trait, ensuring
/// that the operations of addition, subtraction, and multiplication are performed in a field suitable
/// for NTT. This is crucial for the security and correctness of cryptographic operations based on RLWE.
///
/// The fields `a` and `b` are kept private within the crate to maintain encapsulation and are
/// accessible through public API functions that enforce any necessary invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NTTRLWE<F: NTTField> {
    /// Represents the first component in the RLWE structure.
    pub(crate) a: NTTPolynomial<F>,
    /// Represents the second component in the RLWE structure.
    pub(crate) b: NTTPolynomial<F>,
}

impl<F: NTTField> From<RLWE<F>> for NTTRLWE<F> {
    #[inline]
    fn from(c: RLWE<F>) -> Self {
        Self {
            a: <NTTPolynomial<F>>::from(c.a),
            b: <NTTPolynomial<F>>::from(c.b),
        }
    }
}

impl<F: NTTField> From<(Polynomial<F>, Polynomial<F>)> for NTTRLWE<F> {
    #[inline]
    fn from((a, b): (Polynomial<F>, Polynomial<F>)) -> Self {
        Self {
            a: <NTTPolynomial<F>>::from(a),
            b: <NTTPolynomial<F>>::from(b),
        }
    }
}

impl<F: NTTField> NTTRLWE<F> {
    /// Creates a new [`NTTRLWE<F>`].
    #[inline]
    pub fn new(a: NTTPolynomial<F>, b: NTTPolynomial<F>) -> Self {
        Self { a, b }
    }

    /// Creates a new [`NTTRLWE<F>`] with reference of [`NTTPolynomial<F>`].
    #[inline]
    pub fn from_ref(a: &NTTPolynomial<F>, b: &NTTPolynomial<F>) -> Self {
        Self {
            a: a.clone(),
            b: b.clone(),
        }
    }

    /// Returns a reference to the a of this [`NTTRLWE<F>`].
    #[inline]
    pub fn a(&self) -> &NTTPolynomial<F> {
        &self.a
    }

    /// Returns a mutable reference to the a of this [`NTTRLWE<F>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut NTTPolynomial<F> {
        &mut self.a
    }

    /// Returns a reference to the b of this [`NTTRLWE<F>`].
    #[inline]
    pub fn b(&self) -> &NTTPolynomial<F> {
        &self.b
    }

    /// Returns a mutable reference to the b of this [`NTTRLWE<F>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut NTTPolynomial<F> {
        &mut self.b
    }

    /// Performs a multiplication on the `self` [`NTTRLWE<F>`] with another `poly` [`Polynomial<F>`],
    /// return a [`RLWE<F>`].
    #[inline]
    pub fn mul_with_polynomial(&self, poly: &Polynomial<F>) -> RLWE<F> {
        let ntt_poly = <NTTPolynomial<F>>::from(poly);
        RLWE {
            a: <Polynomial<F>>::from(&ntt_poly * &self.a),
            b: <Polynomial<F>>::from(ntt_poly * &self.b),
        }
    }
}
