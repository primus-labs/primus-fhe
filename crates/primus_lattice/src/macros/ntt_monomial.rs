//! NTT-domain monomial products with one shared transform per ciphertext.

macro_rules! impl_ntt_monomial {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Multiplies every ciphertext polynomial by `X^exponent` in the NTT domain.
            ///
            /// Generates the monomial evaluations once in `scratch`, then reuses
            /// them across all components and gadget levels. No allocation or
            /// coefficient-domain conversion is performed.
            ///
            /// # Correctness
            ///
            /// Let `N = ntt.poly_length().get()`. Storage must contain complete
            /// polynomials in that table's evaluation order, with canonical
            /// residues under the same modulus as `modulus` and `ntt`.
            /// Require `exponent < 2 * N`. The result remains canonical.
            /// Scratch has exactly `N` elements and needs no initialization.
            ///
            /// # Panics
            ///
            /// Panics if the scratch length differs from the table's polynomial length.
            #[inline]
            pub fn mul_monomial_assign<M, Table>(
                &mut self,
                exponent: usize,
                modulus: M,
                ntt: &Table,
                scratch: &mut [T],
            ) where
                M: primus_reduce::FieldContext<T>,
                Table: primus_ntt::MonomialNttTable<ValueT = T>,
            {
                debug_assert!(exponent < 2 * ntt.poly_length().get());
                ntt.transform_coeff_one_monomial(exponent, scratch);
                self.mul_ntt_polynomial_assign(&primus_poly::NttPolynomial(&*scratch), modulus);
            }

            /// Accumulates `self += rhs * X^exponent` in the NTT domain.
            ///
            /// # Correctness
            ///
            /// Inherits the contracts and allocation behavior of
            /// [`Self::mul_monomial_assign`]. Both ciphertexts have equal lengths,
            /// matching layouts and compatible keys; gadget bases and level/row
            /// order must match. The accumulator is not cleared.
            ///
            /// # Panics
            ///
            /// Panics if the scratch length differs from the table's polynomial length.
            #[inline]
            pub fn add_mul_monomial_assign<M, Table, A>(
                &mut self,
                rhs: &$cipher<A>,
                exponent: usize,
                modulus: M,
                ntt: &Table,
                scratch: &mut [T],
            ) where
                M: primus_reduce::FieldContext<T>,
                Table: primus_ntt::MonomialNttTable<ValueT = T>,
                A: primus_data::Data<Elem = T>,
            {
                debug_assert!(exponent < 2 * ntt.poly_length().get());
                ntt.transform_coeff_one_monomial(exponent, scratch);
                self.add_mul_ntt_polynomial_assign(
                    rhs,
                    &primus_poly::NttPolynomial(&*scratch),
                    modulus,
                );
            }
        }

        impl<S, T> $cipher<S>
        where
            S: primus_data::Data<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Writes `output = self * X^exponent` in the NTT domain.
            ///
            /// # Correctness
            ///
            /// Inherits the contracts and allocation behavior of
            /// [`Self::mul_monomial_assign`]. Input and output have equal lengths
            /// and matching layouts and gadget bases. Output is fully overwritten.
            ///
            /// # Panics
            ///
            /// Panics if the scratch length differs from the table's polynomial length.
            #[inline]
            pub fn mul_monomial_to<M, Table, A>(
                &self,
                exponent: usize,
                output: &mut $cipher<A>,
                modulus: M,
                ntt: &Table,
                scratch: &mut [T],
            ) where
                M: primus_reduce::FieldContext<T>,
                Table: primus_ntt::MonomialNttTable<ValueT = T>,
                A: primus_data::DataMut<Elem = T>,
            {
                debug_assert!(exponent < 2 * ntt.poly_length().get());
                ntt.transform_coeff_one_monomial(exponent, scratch);
                self.mul_ntt_polynomial_to(&primus_poly::NttPolynomial(&*scratch), output, modulus);
            }

            /// Writes `output = self - rhs * X^exponent` in the NTT domain.
            ///
            /// Shares one monomial transform across all ciphertext polynomials
            /// and fuses each product/subtraction, without a temporary ciphertext.
            ///
            /// # Correctness
            ///
            /// Inherits the contracts and allocation behavior of
            /// [`Self::mul_monomial_assign`]. All ciphertexts have equal lengths,
            /// matching layouts and compatible keys; gadget bases and level/row
            /// order must match. Output is fully overwritten with canonical values.
            ///
            /// # Panics
            ///
            /// Panics if the scratch length differs from the table's polynomial length.
            #[inline]
            pub fn sub_mul_monomial_to<M, Table, A, B>(
                &self,
                rhs: &$cipher<A>,
                exponent: usize,
                output: &mut $cipher<B>,
                modulus: M,
                ntt: &Table,
                scratch: &mut [T],
            ) where
                M: primus_reduce::FieldContext<T>,
                Table: primus_ntt::MonomialNttTable<ValueT = T>,
                A: primus_data::Data<Elem = T>,
                B: primus_data::DataMut<Elem = T>,
            {
                let poly_length = ntt.poly_length().get();
                debug_assert!(exponent < 2 * poly_length);
                debug_assert_eq!(
                    self.as_ref().len(),
                    rhs.as_ref().len(),
                    "ciphertext length mismatch"
                );
                debug_assert_eq!(
                    self.as_ref().len(),
                    output.as_ref().len(),
                    "ciphertext length mismatch"
                );
                // Absorb subtraction into the shared factor to use one FMA per
                // evaluation, avoiding a separate product or ciphertext copy.
                ntt.transform_coeff_minus_one_monomial(exponent, scratch);
                for ((lhs, rhs), output) in self
                    .as_ref()
                    .chunks_exact(poly_length)
                    .zip(rhs.as_ref().chunks_exact(poly_length))
                    .zip(output.as_mut().chunks_exact_mut(poly_length))
                {
                    modulus.reduce_mul_add_slice_to(rhs, scratch, lhs, output);
                }
            }
        }
    };
}
