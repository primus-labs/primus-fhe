//! RNS factor arithmetic.

macro_rules! impl_mul_factor_multiple_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Multiplies each modulus block by its precomputed factor in place.
            ///
            /// # Correctness
            ///
            /// Components are stored consecutively; each contains one length-`poly_length`
            /// block per modulus, in `moduli` order. `poly_length` and `moduli.len()`
            /// must be nonzero, `rns_poly_len = poly_length * moduli.len()`, and
            /// ciphertext lengths must be multiples of `rns_poly_len`.
            /// All operands must have equal lengths, the same ordered modulus base,
            /// and the same coefficient or NTT representation.
            /// `factors` contains one precomputed factor for each modulus in order.
            /// Each factor must match its modulus; values must satisfy its input range.
            ///
            /// # Panics
            ///
            /// Panics when a zero chunk length is used. Other layout requirements
            /// are caller obligations; debug assertions do not provide release validation.
            #[inline]
            pub fn mul_factor_assign<F>(
                &mut self,
                factors: &primus_rns::ResidueFactors<impl primus_data::Data<Elem = F>>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[T],
            ) where
                F: Copy + primus_factor::FactorSliceOps<T>,
            {
                debug_assert_eq!(factors.len(), moduli.len(), "RNS scalar count mismatch");
                for output in self.as_mut().chunks_exact_mut(rns_poly_len) {
                    for (output, &factor, &modulus) in itertools::izip!(
                        output.chunks_exact_mut(poly_length),
                        factors.iter(),
                        moduli
                    ) {
                        factor.factor_mul_slice_assign(output, modulus);
                    }
                }
            }

            /// Accumulates `self += rhs * factors` without clearing `self` or allocating.
            ///
            /// # Correctness
            ///
            /// Both ciphertexts must have the same length, layout, representation,
            /// and compatible key semantics. Gadget bases and level/row order must
            /// match. Components are consecutive RNS polynomials, each containing
            /// one length-`poly_length` block per modulus in `moduli` order.
            /// `poly_length` and the modulus count must be nonzero, and
            /// `rns_poly_len = poly_length * moduli.len()`. Ciphertext lengths must
            /// be multiples of `rns_poly_len`. `factors` must have one entry per
            /// modulus in that same order, applied to every ciphertext component.
            /// Input and accumulator values must be canonical residues, and results
            /// remain canonical. Each factor must be precomputed for its
            /// corresponding modulus.
            ///
            /// # Panics
            ///
            /// Panics when a zero chunk length is used. Other layout requirements
            /// are caller obligations; debug assertions do not provide release validation.
            #[inline]
            pub fn add_mul_factor_assign<F, A>(
                &mut self,
                rhs: &$cipher<A>,
                factors: &primus_rns::ResidueFactors<impl primus_data::Data<Elem = F>>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[T],
            ) where
                F: Copy + primus_factor::FactorSliceOps<T>,
                A: primus_data::Data<Elem = T>,
            {
                debug_assert_eq!(factors.len(), moduli.len(), "RNS scalar count mismatch");
                debug_assert_eq!(
                    self.as_ref().len(),
                    rhs.as_ref().len(),
                    "RNS operand length mismatch"
                );
                for (acc, rhs) in self
                    .as_mut()
                    .chunks_exact_mut(rns_poly_len)
                    .zip(rhs.as_ref().chunks_exact(rns_poly_len))
                {
                    for (acc, rhs, &factor, &modulus) in itertools::izip!(
                        acc.chunks_exact_mut(poly_length),
                        rhs.chunks_exact(poly_length),
                        factors.iter(),
                        moduli
                    ) {
                        factor.add_factor_mul_slice_assign(acc, rhs, modulus);
                    }
                }
            }

            /// Accumulates `self -= rhs * factors` without clearing `self` or allocating.
            ///
            /// # Correctness
            ///
            /// Both ciphertexts must have the same length, layout, representation,
            /// and compatible key semantics. Gadget bases and level/row order must
            /// match. Components are consecutive RNS polynomials, each containing
            /// one length-`poly_length` block per modulus in `moduli` order.
            /// `poly_length` and the modulus count must be nonzero, and
            /// `rns_poly_len = poly_length * moduli.len()`. Ciphertext lengths must
            /// be multiples of `rns_poly_len`. `factors` must have one entry per
            /// modulus in that same order, applied to every ciphertext component.
            /// Input and accumulator values must be canonical residues, and results
            /// remain canonical. Each factor must be precomputed for its
            /// corresponding modulus.
            ///
            /// # Panics
            ///
            /// Panics when a zero chunk length is used. Other layout requirements
            /// are caller obligations; debug assertions do not provide release validation.
            #[inline]
            pub fn sub_mul_factor_assign<F, A>(
                &mut self,
                rhs: &$cipher<A>,
                factors: &primus_rns::ResidueFactors<impl primus_data::Data<Elem = F>>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[T],
            ) where
                F: Copy + primus_factor::FactorSliceOps<T>,
                A: primus_data::Data<Elem = T>,
            {
                debug_assert_eq!(factors.len(), moduli.len(), "RNS scalar count mismatch");
                debug_assert_eq!(
                    self.as_ref().len(),
                    rhs.as_ref().len(),
                    "RNS operand length mismatch"
                );
                for (acc, rhs) in self
                    .as_mut()
                    .chunks_exact_mut(rns_poly_len)
                    .zip(rhs.as_ref().chunks_exact(rns_poly_len))
                {
                    for (acc, rhs, &factor, &modulus) in itertools::izip!(
                        acc.chunks_exact_mut(poly_length),
                        rhs.chunks_exact(poly_length),
                        factors.iter(),
                        moduli
                    ) {
                        factor.sub_factor_mul_slice_assign(acc, rhs, modulus);
                    }
                }
            }
        }
        impl<S, T> $cipher<S>
        where
            S: primus_data::Data<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Writes the factor product into `output`, overwriting all components.
            ///
            /// # Correctness
            ///
            /// Components are stored consecutively; each contains one length-`poly_length`
            /// block per modulus, in `moduli` order. `poly_length` and `moduli.len()`
            /// must be nonzero, `rns_poly_len = poly_length * moduli.len()`, and
            /// ciphertext lengths must be multiples of `rns_poly_len`.
            /// All operands must have equal lengths, the same ordered modulus base,
            /// and the same coefficient or NTT representation.
            /// `factors` contains one precomputed factor for each modulus in order.
            /// Each factor must match its modulus; values must satisfy its input range.
            ///
            /// # Panics
            ///
            /// Panics when a zero chunk length is used. Other layout requirements
            /// are caller obligations; debug assertions do not provide release validation.
            #[inline]
            pub fn mul_factor_to<F, A>(
                &self,
                factors: &primus_rns::ResidueFactors<impl primus_data::Data<Elem = F>>,
                output: &mut $cipher<A>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[T],
            ) where
                F: Copy + primus_factor::FactorSliceOps<T>,
                A: primus_data::DataMut<Elem = T>,
            {
                debug_assert_eq!(factors.len(), moduli.len(), "RNS scalar count mismatch");
                debug_assert_eq!(
                    self.as_ref().len(),
                    output.as_ref().len(),
                    "RNS output length mismatch"
                );
                for (input, output) in self
                    .as_ref()
                    .chunks_exact(rns_poly_len)
                    .zip(output.as_mut().chunks_exact_mut(rns_poly_len))
                {
                    for (input, output, &factor, &modulus) in itertools::izip!(
                        input.chunks_exact(poly_length),
                        output.chunks_exact_mut(poly_length),
                        factors.iter(),
                        moduli
                    ) {
                        factor.factor_mul_slice_to(input, output, modulus);
                    }
                }
            }
        }
    };
}
