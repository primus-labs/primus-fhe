use algebra::{transformation::AbstractNTT, NTTField, NTTPolynomial, Polynomial, Ring};
use num_traits::Zero;

use crate::{GadgetRLWE, NTTGadgetRLWE, LWE, NTTRGSW, RGSW};

use super::utils::{ntt_add_mul_assign, ntt_add_mul_assign_ref};

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

impl<F: NTTField> From<NTTRLWE<F>> for RLWE<F> {
    #[inline]
    fn from(ntt_rlwe: NTTRLWE<F>) -> Self {
        Self {
            a: <Polynomial<F>>::from(ntt_rlwe.a),
            b: <Polynomial<F>>::from(ntt_rlwe.b),
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
    /// Both `a` and `b` polynomials of the [`RLWE<F>`] are initialized with zero coefficients.
    ///
    /// # Arguments
    ///
    /// * `coeff_count` - The number of coefficients in the polynomial.
    ///
    /// # Returns
    ///
    /// A new [`RLWE<F>`] where both `a` and `b` polynomials are initialized to zero.
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
        &self.a
    }

    /// Returns a mutable reference to the `a` of this [`RLWE<F>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut Polynomial<F> {
        &mut self.a
    }

    /// Returns a reference to the `b` of this [`RLWE<F>`].
    #[inline]
    pub fn b(&self) -> &Polynomial<F> {
        &self.b
    }

    /// Returns a mutable reference to the `b` of this [`RLWE<F>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut Polynomial<F> {
        &mut self.b
    }

    /// Perform element-wise addition of two [`RLWE<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `add_element_wise`.
    #[inline]
    pub fn add_element_wise_ref(&self, rhs: &Self) -> Self {
        Self {
            a: self.a() + rhs.a(),
            b: self.b() + rhs.b(),
        }
    }

    /// Perform element-wise addition of two [`RLWE<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is not a reference.
    /// If your `self` is a reference, you can use function `add_element_wise_ref`.
    #[inline]
    pub fn add_element_wise(self, rhs: &Self) -> Self {
        Self {
            a: self.a + rhs.a(),
            b: self.b + rhs.b(),
        }
    }

    /// Perform element-wise subtraction of two [`RLWE<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `sub_element_wise`.
    #[inline]
    pub fn sub_element_wise_ref(&self, rhs: &Self) -> Self {
        Self {
            a: self.a() - rhs.a(),
            b: self.b() - rhs.b(),
        }
    }

    /// Perform element-wise subtraction of two [`RLWE<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is not a reference.
    /// If your `self` is a reference, you can use function `sub_element_wise_ref`.
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
        self.a += rhs.a();
        self.b += rhs.b();
    }

    /// Performs an in-place element-wise subtraction
    /// on the `self` [`RLWE<F>`] with another `rhs` [`RLWE<F>`].
    #[inline]
    pub fn sub_inplace_element_wise(&mut self, rhs: &Self) {
        self.a -= rhs.a();
        self.b -= rhs.b();
    }

    /// Performs a multiplication on the `self` [`RLWE<F>`] with another `poly` [`Polynomial<F>`],
    /// return a [`RLWE<F>`].
    #[inline]
    pub fn mul_polynomial(&self, poly: Polynomial<F>) -> Self {
        let ntt_poly = <NTTPolynomial<F>>::from(poly);
        Self {
            a: self.a() * &ntt_poly,
            b: self.b() * ntt_poly,
        }
    }

    /// Performs `self + gadget_rlwe * polynomial`.
    #[inline]
    pub fn add_gadget_rlwe_mul_polynomial(
        self,
        gadget_rlwe: &GadgetRLWE<F>,
        polynomial: &Polynomial<F>,
    ) -> RLWE<F> {
        let decomposed = polynomial.clone().decompose(gadget_rlwe.basis());
        gadget_rlwe.mul_decomposed_polynomial_slice_add_rlwe(decomposed, self)
    }

    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_lwe(&self) -> LWE<F> {
        let mut a: Vec<F> = self.a.as_slice().iter().map(|&x| -x).collect();
        a[1..].reverse();
        a[0] = -a[0];

        let b = self.b()[0];

        LWE::<F>::new(a, b)
    }

    /// Perform [`RLWE<F>`] multiply with `Y^r` for functional bootstrapping where `Y = X^(2N/q)`.
    #[inline]
    pub fn mul_monic_monomial<R: Ring>(
        &self,
        // N
        rlwe_dimension: usize,
        // 2N/q
        twice_rlwe_dimension_div_lwe_modulus: usize,
        r: R,
    ) -> Self {
        let r = r.cast_into_usize() * twice_rlwe_dimension_div_lwe_modulus;
        if r <= rlwe_dimension {
            #[inline]
            fn rotate<F: NTTField>(p: &Polynomial<F>, r: usize) -> Polynomial<F> {
                let mut p = p.clone();
                let s = p.as_mut_slice();
                s.rotate_right(r);
                s[0..r].iter_mut().for_each(|v| *v = -*v);
                p
            }
            Self {
                a: rotate(&self.a, r),
                b: rotate(&self.b, r),
            }
        } else {
            #[inline]
            fn rotate<F: NTTField>(p: &Polynomial<F>, r: usize) -> Polynomial<F> {
                let mut p = p.clone();
                let s = p.as_mut_slice();
                s.rotate_right(r);
                s[r..].iter_mut().for_each(|v| *v = -*v);
                p
            }
            let r = r - rlwe_dimension;
            Self {
                a: rotate(&self.a, r),
                b: rotate(&self.b, r),
            }
        }
    }

    /// Perform [`RLWE<F>`] multiply with `Y^r` for functional bootstrapping where `Y = X^(2N/q)`.
    #[inline]
    pub fn mul_monic_monomial_inplace<R: Ring>(
        &self,
        // N
        rlwe_dimension: usize,
        // 2N/q
        twice_rlwe_dimension_div_lwe_modulus: usize,
        r: R,
        dst: &mut RLWE<F>,
    ) {
        let r = r.cast_into_usize() * twice_rlwe_dimension_div_lwe_modulus;
        if r <= rlwe_dimension {
            #[inline]
            fn rotate<F: NTTField>(
                src: &Polynomial<F>,
                r: usize,
                n_sub_r: usize,
                dst: &mut Polynomial<F>,
            ) {
                let src = src.as_slice();
                let dst = dst.as_mut_slice();
                dst[0..r]
                    .iter_mut()
                    .zip(&src[n_sub_r..])
                    .for_each(|(x, &y)| *x = -y);
                dst[r..]
                    .iter_mut()
                    .zip(&src[0..n_sub_r])
                    .for_each(|(x, &y)| *x = y);
            }

            let n_sub_r = rlwe_dimension - r;
            rotate(&self.a, r, n_sub_r, &mut dst.a);
            rotate(&self.b, r, n_sub_r, &mut dst.b);
        } else {
            #[inline]
            fn rotate<F: NTTField>(
                src: &Polynomial<F>,
                r: usize,
                n_sub_r: usize,
                dst: &mut Polynomial<F>,
            ) {
                let src = src.as_slice();
                let dst = dst.as_mut_slice();
                dst[0..r]
                    .iter_mut()
                    .zip(&src[n_sub_r..])
                    .for_each(|(x, &y)| *x = y);
                dst[r..]
                    .iter_mut()
                    .zip(&src[0..n_sub_r])
                    .for_each(|(x, &y)| *x = -y);
            }

            let r = r - rlwe_dimension;
            let n_sub_r = rlwe_dimension - r;
            rotate(&self.a, r, n_sub_r, &mut dst.a);
            rotate(&self.b, r, n_sub_r, &mut dst.b);
        }
    }

    /// Perform [`RLWE<F>`] multiply with `Y^r - 1` for functional bootstrapping where `Y = X^(2N/q)`.
    #[inline]
    pub fn mul_monic_monomial_sub_one<R: Ring>(
        &self,
        // N
        rlwe_dimension: usize,
        // 2N/q
        twice_rlwe_dimension_div_lwe_modulus: usize,
        r: R,
    ) -> Self {
        self.mul_monic_monomial(rlwe_dimension, twice_rlwe_dimension_div_lwe_modulus, r)
            .sub_element_wise(self)
    }

    /// Perform [`RLWE<F>`] multiply with `Y^r - 1` for functional bootstrapping where `Y = X^(2N/q)`.
    #[inline]
    pub fn mul_monic_monomial_sub_one_inplace<R: Ring>(
        &self,
        // N
        rlwe_dimension: usize,
        // 2N/q
        twice_rlwe_dimension_div_lwe_modulus: usize,
        r: R,
        dst: &mut RLWE<F>,
    ) {
        self.mul_monic_monomial_inplace(
            rlwe_dimension,
            twice_rlwe_dimension_div_lwe_modulus,
            r,
            dst,
        );
        dst.sub_inplace_element_wise(self);
    }

    /// Performs a multiplication on the `self` [`RLWE<F>`] with another `small_rgsw` [`RGSW<F>`],
    /// return a [`RLWE<F>`].
    ///
    /// # Attention
    /// The message of **`small_rgsw`** is restricted to small messages `m`, typically `m = ±Xⁱ`
    #[inline]
    pub fn mul_small_rgsw(&self, small_rgsw: &RGSW<F>) -> RLWE<F> {
        small_rgsw
            .c_neg_s_m()
            .mul_polynomial(self.a())
            .add_gadget_rlwe_mul_polynomial(small_rgsw.c_m(), self.b())
    }

    /// Performs a multiplication on the `self` [`RLWE<F>`] with another `small_ntt_rgsw` [`NTTRGSW<F>`],
    /// return a [`RLWE<F>`].
    ///
    /// # Attention
    /// The message of **`small_ntt_rgsw`** is restricted to small messages `m`, typically `m = ±Xⁱ`
    #[inline]
    pub fn mul_small_ntt_rgsw(&self, small_ntt_rgsw: &NTTRGSW<F>) -> RLWE<F> {
        small_ntt_rgsw
            .c_neg_s_m()
            .mul_polynomial(self.a())
            .add_gadget_rlwe_mul_polynomial(small_ntt_rgsw.c_m(), self.b())
            .into()
    }

    /// Performs a multiplication on the `self` [`RLWE<F>`] with another `small_ntt_rgsw` [`NTTRGSW<F>`],
    /// output the [`RLWE<F>`] result into `dst`.
    ///
    /// # Attention
    /// The message of **`small_ntt_rgsw`** is restricted to small messages `m`, typically `m = ±Xⁱ`
    #[inline]
    pub fn mul_small_ntt_rgsw_inplace(
        &self,
        small_ntt_rgsw: &NTTRGSW<F>,
        // Pre allocate space for decomposition
        decompose_space: &mut [Polynomial<F>],
        // Pre allocate space for ntt rlwe
        ntt_rlwe_space: &mut NTTRLWE<F>,
        // Output destination
        dst: &mut RLWE<F>,
    ) {
        small_ntt_rgsw.c_neg_s_m().mul_polynomial_inplace(
            self.a(),
            decompose_space,
            ntt_rlwe_space,
            dst.a_mut(),
        );

        ntt_rlwe_space.add_gadget_rlwe_mul_polynomial_inplace(
            small_ntt_rgsw.c_m(),
            self.b(),
            decompose_space,
            dst.a_mut(),
        );

        ntt_rlwe_space.inverse_transform_inplace(dst)
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
    fn from(rlwe: RLWE<F>) -> Self {
        Self {
            a: <NTTPolynomial<F>>::from(rlwe.a),
            b: <NTTPolynomial<F>>::from(rlwe.b),
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

    /// Creates a [`NTTRLWE<F>`] with all entries equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> NTTRLWE<F> {
        Self {
            a: <NTTPolynomial<F>>::zero_with_coeff_count(coeff_count),
            b: <NTTPolynomial<F>>::zero_with_coeff_count(coeff_count),
        }
    }

    /// Creates a [`NTTRLWE<F>`] with all entries equal to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.a.set_zero();
        self.b.set_zero();
    }

    /// ntt inverse transform
    pub fn inverse_transform_inplace(&self, dst: &mut RLWE<F>) {
        let coeff_count = dst.a.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();

        dst.a_mut()
            .iter_mut()
            .zip(self.a())
            .for_each(|(x, &y)| *x = y);

        dst.b_mut()
            .iter_mut()
            .zip(self.b())
            .for_each(|(x, &y)| *x = y);

        ntt_table.inverse_transform_slice(dst.a_mut().as_mut_slice());
        ntt_table.inverse_transform_slice(dst.b_mut().as_mut_slice());
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

    /// Perform element-wise addition of two [`NTTRLWE<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `add_element_wise`.
    #[inline]
    pub fn add_element_wise_ref(&self, rhs: &Self) -> Self {
        Self {
            a: self.a() + rhs.a(),
            b: self.b() + rhs.b(),
        }
    }

    /// Perform element-wise addition of two [`NTTRLWE<F>`].
    #[inline]
    pub fn add_element_wise(self, rhs: &Self) -> Self {
        Self {
            a: self.a + rhs.a(),
            b: self.b + rhs.b(),
        }
    }

    /// Perform element-wise subtraction of two [`NTTRLWE<F>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `sub_element_wise`.
    #[inline]
    pub fn sub_element_wise_ref(&self, rhs: &Self) -> Self {
        Self {
            a: self.a() - rhs.a(),
            b: self.b() - rhs.b(),
        }
    }

    /// Perform element-wise subtraction of two [`NTTRLWE<F>`].
    #[inline]
    pub fn sub_element_wise(self, rhs: &Self) -> Self {
        Self {
            a: self.a - rhs.a(),
            b: self.b - rhs.b(),
        }
    }

    /// Performs a multiplication on the `self` [`NTTRLWE<F>`] with another `polynomial` [`Polynomial<F>`],
    /// return a [`NTTRLWE<F>`].
    #[inline]
    pub fn mul_polynomial(&self, polynomial: Polynomial<F>) -> NTTRLWE<F> {
        let ntt_polynomial = <NTTPolynomial<F>>::from(polynomial);
        NTTRLWE {
            a: &self.a * &ntt_polynomial,
            b: &self.b * ntt_polynomial,
        }
    }

    /// Performs `self = self + ntt_rlwe * polynomial`.
    #[inline]
    pub fn add_rlwe_mul_polynomial_inplace(&mut self, rhs: &NTTRLWE<F>, polynomial: Polynomial<F>) {
        let ntt_polynomial = <NTTPolynomial<F>>::from(polynomial);
        ntt_add_mul_assign_ref(&mut self.a, &rhs.a, &ntt_polynomial);
        ntt_add_mul_assign(&mut self.b, &rhs.b, ntt_polynomial);
    }

    /// Performs `self = self + ntt_rlwe * ntt_polynomial`.
    #[inline]
    pub fn add_rlwe_mul_ntt_polynomial_inplace(&mut self, rhs: &NTTRLWE<F>, ntt_polynomial: &[F]) {
        ntt_add_mul_assign_ref(&mut self.a, &rhs.a, ntt_polynomial);
        ntt_add_mul_assign_ref(&mut self.b, &rhs.b, ntt_polynomial);
    }

    /// Performs `self + gadget_rlwe * polynomial`.
    #[inline]
    pub fn add_gadget_rlwe_mul_polynomial(
        self,
        gadget_rlwe: &NTTGadgetRLWE<F>,
        polynomial: &Polynomial<F>,
    ) -> NTTRLWE<F> {
        let decomposed = polynomial.clone().decompose(gadget_rlwe.basis());
        gadget_rlwe.mul_decomposed_polynomial_slice_add_rlwe(decomposed, self)
    }

    /// Performs `self = self + gadget_rlwe * polynomial`.
    #[inline]
    pub fn add_gadget_rlwe_mul_polynomial_inplace(
        &mut self,
        gadget_rlwe: &NTTGadgetRLWE<F>,
        polynomial: &Polynomial<F>,
        decompose_space: &mut [Polynomial<F>],
        polynomial_space: &mut Polynomial<F>,
    ) {
        let coeff_count = polynomial.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();

        polynomial_space
            .iter_mut()
            .zip(polynomial)
            .for_each(|(x, &y)| *x = y);

        polynomial_space.decompose_inplace(gadget_rlwe.basis(), decompose_space);

        gadget_rlwe
            .iter()
            .zip(decompose_space)
            .for_each(|(g, d_p)| {
                let d_s = d_p.as_mut_slice();
                ntt_table.transform_slice(d_s);
                self.add_rlwe_mul_ntt_polynomial_inplace(g, d_s);
            });
    }

    /// Performs `self - gadget_rlwe * polynomial`.
    #[inline]
    pub fn sub_gadget_rlwe_mul_polynomial(
        self,
        gadget_rlwe: &NTTGadgetRLWE<F>,
        polynomial: Polynomial<F>,
    ) -> NTTRLWE<F> {
        let decomposed = (-polynomial).decompose(gadget_rlwe.basis());
        gadget_rlwe.mul_decomposed_polynomial_slice_add_rlwe(decomposed, self)
    }

    /// Performs `self = self - gadget_rlwe * polynomial`.
    #[inline]
    pub fn sub_gadget_rlwe_mul_polynomial_inplace(
        &mut self,
        gadget_rlwe: &NTTGadgetRLWE<F>,
        polynomial: Polynomial<F>,
        decompose_space: &mut [Polynomial<F>],
    ) {
        let coeff_count = polynomial.coeff_count();
        debug_assert!(coeff_count.is_power_of_two());
        let ntt_table = F::get_ntt_table(coeff_count.trailing_zeros()).unwrap();

        (-polynomial).decompose_inplace(gadget_rlwe.basis(), decompose_space);

        gadget_rlwe
            .iter()
            .zip(decompose_space)
            .for_each(|(g, d_p)| {
                let d_s = d_p.as_mut_slice();
                ntt_table.transform_slice(d_s);
                self.add_rlwe_mul_ntt_polynomial_inplace(g, d_s);
            });
    }
}
