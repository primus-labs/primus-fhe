//! Pointwise Fourier ciphertext arithmetic.

/// Pointwise arithmetic shared by Fourier ciphertexts.
macro_rules! impl_fourier_basic_operation {
    ($cipher:ident) => {
        impl<S> $cipher<S>
        where
            S: primus_data::DataMut<Elem = num_complex::Complex64>,
        {
            /// Performs pointwise addition in place.
            ///
            /// # Correctness
            ///
            /// All ciphertexts must use compatible keys, the same FFT table, evaluation
            /// order and scale, and matching layouts (including gadget rows and levels).
            /// Operand lengths must match.
            #[inline]
            pub fn add_assign<A>(&mut self, rhs: &$cipher<A>)
            where
                A: primus_data::Data<Elem = num_complex::Complex64>,
            {
                primus_poly::FourierPolynomial(self.as_mut())
                    .add_assign(&primus_poly::FourierPolynomial(rhs.as_ref()));
            }

            /// Performs pointwise subtraction in place.
            ///
            /// # Correctness
            ///
            /// All ciphertexts must use compatible keys, the same FFT table, evaluation
            /// order and scale, and matching layouts (including gadget rows and levels).
            /// Operand lengths must match.
            #[inline]
            pub fn sub_assign<A>(&mut self, rhs: &$cipher<A>)
            where
                A: primus_data::Data<Elem = num_complex::Complex64>,
            {
                primus_poly::FourierPolynomial(self.as_mut())
                    .sub_assign(&primus_poly::FourierPolynomial(rhs.as_ref()));
            }

            /// Performs pointwise negation in place.
            ///
            /// # Correctness
            ///
            /// Storage must contain a complete Fourier ciphertext in its original
            /// layout and scale. Every stored complex value is transformed.
            #[inline]
            pub fn neg_assign(&mut self) {
                primus_poly::FourierPolynomial(self.as_mut()).neg_assign();
            }

            /// Performs real scalar multiplication in place.
            ///
            /// # Correctness
            ///
            /// Storage must contain a complete Fourier ciphertext in its original
            /// layout and scale. Every stored complex value is transformed.
            /// Choose finite inputs and a finite scalar whose product remains
            /// representable in `f64`; the operation does not bound numerical error.
            #[inline]
            pub fn mul_scalar_assign(&mut self, scalar: f64) {
                primus_poly::FourierPolynomial(self.as_mut()).mul_scalar_assign(scalar);
            }
        }
        impl<S> $cipher<S>
        where
            S: primus_data::Data<Elem = num_complex::Complex64>,
        {
            /// Writes `output = self + rhs` into existing storage.
            ///
            /// # Correctness
            ///
            /// All ciphertexts must use compatible keys, the same FFT table, evaluation
            /// order and scale, and matching layouts (including gadget rows and levels).
            /// Input and output lengths must match.
            #[inline]
            pub fn add_to<A, B>(&self, rhs: &$cipher<A>, output: &mut $cipher<B>)
            where
                A: primus_data::Data<Elem = num_complex::Complex64>,
                B: primus_data::DataMut<Elem = num_complex::Complex64>,
            {
                primus_poly::FourierPolynomial(self.as_ref()).add_to(
                    &primus_poly::FourierPolynomial(rhs.as_ref()),
                    &mut primus_poly::FourierPolynomial(output.as_mut()),
                );
            }

            /// Writes `output = self - rhs` into existing storage.
            ///
            /// # Correctness
            ///
            /// All ciphertexts must use compatible keys, the same FFT table, evaluation
            /// order and scale, and matching layouts (including gadget rows and levels).
            /// Input and output lengths must match.
            #[inline]
            pub fn sub_to<A, B>(&self, rhs: &$cipher<A>, output: &mut $cipher<B>)
            where
                A: primus_data::Data<Elem = num_complex::Complex64>,
                B: primus_data::DataMut<Elem = num_complex::Complex64>,
            {
                primus_poly::FourierPolynomial(self.as_ref()).sub_to(
                    &primus_poly::FourierPolynomial(rhs.as_ref()),
                    &mut primus_poly::FourierPolynomial(output.as_mut()),
                );
            }

            /// Writes `output = -self` into existing storage.
            ///
            /// # Correctness
            ///
            /// All ciphertexts must use compatible keys, the same FFT table, evaluation
            /// order and scale, and matching layouts (including gadget rows and levels).
            /// Input and output lengths must match.
            #[inline]
            pub fn neg_to<A>(&self, output: &mut $cipher<A>)
            where
                A: primus_data::DataMut<Elem = num_complex::Complex64>,
            {
                primus_poly::FourierPolynomial(self.as_ref())
                    .neg_to(&mut primus_poly::FourierPolynomial(output.as_mut()));
            }

            /// Writes `output = self * scalar` into existing storage.
            ///
            /// # Correctness
            ///
            /// All ciphertexts must use compatible keys, the same FFT table, evaluation
            /// order and scale, and matching layouts (including gadget rows and levels).
            /// Input and output lengths must match.
            /// Choose finite inputs and a finite scalar whose product remains
            /// representable in `f64`; the operation does not bound numerical error.
            #[inline]
            pub fn mul_scalar_to<A>(&self, scalar: f64, output: &mut $cipher<A>)
            where
                A: primus_data::DataMut<Elem = num_complex::Complex64>,
            {
                primus_poly::FourierPolynomial(self.as_ref())
                    .mul_scalar_to(scalar, &mut primus_poly::FourierPolynomial(output.as_mut()));
            }
        }
    };
}

/// Products with one Fourier polynomial, repeated over all ciphertext components.
macro_rules! impl_fourier_polynomial {
    ($cipher:ident) => {
        impl<S> $cipher<S>
        where
            S: primus_data::DataMut<Elem = num_complex::Complex64>,
        {
            /// Multiplies each component by `poly` pointwise, without allocation.
            ///
            /// # Correctness
            ///
            /// `poly` must be nonempty and its length must divide the ciphertext length.
            /// NTRU contains exactly one polynomial, so its length must equal `poly`
            /// length. All values must use the same FFT table and evaluation order. For a torus
            /// ciphertext, `poly` must represent an unscaled integer polynomial, rather
            /// than a normalized torus polynomial, to preserve the ciphertext scale.
            ///
            /// # Panics
            ///
            /// Panics if `poly` is empty.
            #[inline]
            pub fn mul_fourier_polynomial_assign<A>(
                &mut self,
                poly: &primus_poly::FourierPolynomial<A>,
            ) where
                A: primus_data::Data<Elem = num_complex::Complex64>,
            {
                let n = poly.len();
                for output in self.as_mut().chunks_exact_mut(n) {
                    primus_poly::FourierPolynomial(output).mul_assign(poly);
                }
            }

            /// Accumulates `self += rhs * poly` for every component, without allocation.
            ///
            /// # Correctness
            ///
            /// Input and accumulator must have equal lengths, compatible keys and
            /// matching layouts (including gadget rows and levels). They must use the
            /// same FFT table, evaluation order and scale. `poly` must be nonempty and
            /// its length must divide the ciphertext length (equal it for NTRU).
            /// For a torus ciphertext,
            /// `poly` must be transformed as an unscaled integer polynomial.
            ///
            /// # Panics
            ///
            /// Panics if `poly` is empty.
            #[inline]
            pub fn add_mul_fourier_polynomial_assign<A, B>(
                &mut self,
                rhs: &$cipher<A>,
                poly: &primus_poly::FourierPolynomial<B>,
            ) where
                A: primus_data::Data<Elem = num_complex::Complex64>,
                B: primus_data::Data<Elem = num_complex::Complex64>,
            {
                let n = poly.len();
                debug_assert_eq!(
                    self.as_ref().len(),
                    rhs.as_ref().len(),
                    "ciphertext length mismatch"
                );
                for (acc, rhs) in self
                    .as_mut()
                    .chunks_exact_mut(n)
                    .zip(rhs.as_ref().chunks_exact(n))
                {
                    primus_poly::FourierPolynomial(acc)
                        .add_mul_assign(poly, &primus_poly::FourierPolynomial(rhs));
                }
            }
        }
        impl<S> $cipher<S>
        where
            S: primus_data::Data<Elem = num_complex::Complex64>,
        {
            /// Writes `output = self * poly`, multiplying every component pointwise.
            ///
            /// # Correctness
            ///
            /// Input and output must have equal lengths and matching layouts. `poly`
            /// must be nonempty and its length must divide the ciphertext length.
            /// For NTRU the multiplier and ciphertext lengths must be equal.
            /// Both inputs must use the same FFT table and evaluation order. For a
            /// torus ciphertext, `poly` must represent an unscaled integer polynomial.
            /// Output retains the input ciphertext scale; no temporary is allocated.
            ///
            /// # Panics
            ///
            /// Panics if `poly` is empty.
            #[inline]
            pub fn mul_fourier_polynomial_to<A, B>(
                &self,
                poly: &primus_poly::FourierPolynomial<A>,
                output: &mut $cipher<B>,
            ) where
                A: primus_data::Data<Elem = num_complex::Complex64>,
                B: primus_data::DataMut<Elem = num_complex::Complex64>,
            {
                let n = poly.len();
                debug_assert_eq!(
                    self.as_ref().len(),
                    output.as_ref().len(),
                    "ciphertext length mismatch"
                );
                for (input, output) in self
                    .as_ref()
                    .chunks_exact(n)
                    .zip(output.as_mut().chunks_exact_mut(n))
                {
                    primus_poly::FourierPolynomial(input)
                        .mul_to(poly, &mut primus_poly::FourierPolynomial(output));
                }
            }
        }
    };
}
