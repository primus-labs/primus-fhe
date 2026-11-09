//! Fourier monomial subtraction shared by gadget ciphertexts.

macro_rules! impl_fourier_monomial {
    ($cipher:ident) => {
        impl<S> $cipher<S>
        where
            S: primus_data::Data<Elem = primus_fft::Complex64>,
        {
            /// Writes `self - rhs * X^exponent` in Fourier form.
            ///
            /// Transforms one integer-scale monomial and shares it across all ciphertext
            /// polynomials, combining multiplication and subtraction in one pass.
            /// Ciphertexts stay in Fourier form; no storage is allocated.
            ///
            /// # Correctness
            ///
            /// All ciphertexts must have equal lengths and matching ciphertext layouts,
            /// keys and gadget bases. They must use the engine's exact table instance,
            /// evaluation order and normalized torus scale. Each polynomial occupies
            /// `fft.fourier_length()` complex values. `exponent` must be in `0..2N`,
            /// where `N = fft.poly_length().get()`.
            ///
            /// `coefficient_scratch` holds `N` signed-integer bit patterns and
            /// `fourier_scratch` holds `N/2` complex values. Both are overwritten before
            /// use and need no initialization. The integer transform preserves the
            /// ciphertext scale; a torus-scaled monomial would give the wrong result.
            ///
            /// # Panics
            ///
            /// Panics if either scratch length differs from the engine's required length.
            /// Scratch may be partially written before a panic; output is written only
            /// after the monomial transform succeeds.
            #[inline]
            pub fn sub_mul_monomial_to<T, Table, A, B>(
                &self,
                rhs: &$cipher<A>,
                exponent: usize,
                output: &mut $cipher<B>,
                fft: &mut primus_fft::FftEngine<'_, Table>,
                coefficient_scratch: &mut [T],
                fourier_scratch: &mut [primus_fft::Complex64],
            ) where
                T: primus_fft::TorusFftValue,
                Table: primus_fft::FftTable,
                A: primus_data::Data<Elem = primus_fft::Complex64>,
                B: primus_data::DataMut<Elem = primus_fft::Complex64>,
            {
                let poly_length = fft.poly_length().get();
                let fourier_length = fft.fourier_length();
                debug_assert!(exponent < 2 * poly_length);
                debug_assert_eq!(self.as_ref().len(), rhs.as_ref().len());
                debug_assert_eq!(self.as_ref().len(), output.as_ref().len());
                debug_assert_eq!(self.as_ref().len() & (fourier_length - 1), 0);

                coefficient_scratch.fill(T::ZERO);
                // X^(N+j) = -X^j; integer conversion interprets T::MAX as -1.
                let (index, coefficient) = if exponent < poly_length {
                    (exponent, T::ONE)
                } else {
                    (exponent - poly_length, T::MAX)
                };
                coefficient_scratch[index] = coefficient;
                fft.forward_as_integer(coefficient_scratch, fourier_scratch);
                for ((lhs, rhs), output) in self
                    .as_ref()
                    .chunks_exact(fourier_length)
                    .zip(rhs.as_ref().chunks_exact(fourier_length))
                    .zip(output.as_mut().chunks_exact_mut(fourier_length))
                {
                    for (((&lhs, &rhs), &factor), output) in
                        lhs.iter().zip(rhs).zip(&*fourier_scratch).zip(output)
                    {
                        *output = lhs - rhs * factor;
                    }
                }
            }
        }
    };
}
