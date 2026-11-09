//! RNS scalar arithmetic.

macro_rules! impl_mul_scalar_multiple_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Multiplies each modulus block by its scalar residue in place.
            ///
            /// # Correctness
            ///
            /// Components are stored consecutively; each contains one length-`poly_length`
            /// block per modulus, in `moduli` order. `poly_length` and `moduli.len()`
            /// must be nonzero, `rns_poly_len = poly_length * moduli.len()`, and
            /// ciphertext lengths must be multiples of `rns_poly_len`.
            /// All operands must have equal lengths, the same ordered modulus base,
            /// and the same coefficient or NTT representation.
            /// `scalar` contains one residue per modulus, in the same order.
            /// Values and residues must satisfy each modulus multiplication input range.
            ///
            /// # Panics
            ///
            /// Panics when a zero chunk length is used. Other layout requirements
            /// are caller obligations; debug assertions do not provide release validation.
            #[inline]
            pub fn mul_scalar_assign<M>(
                &mut self,
                scalar: &primus_rns::Residues<impl primus_data::Data<Elem = T>>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[M],
            ) where
                M: Copy + primus_reduce::ReduceMulSlice<T>,
            {
                debug_assert_eq!(scalar.len(), moduli.len(), "RNS scalar count mismatch");
                for output in self.as_mut().chunks_exact_mut(rns_poly_len) {
                    for (output, &scalar, &modulus) in itertools::izip!(
                        output.chunks_exact_mut(poly_length),
                        scalar.iter(),
                        moduli
                    ) {
                        modulus.reduce_mul_scalar_slice_assign(output, scalar);
                    }
                }
            }

            /// Accumulates `self += rhs * scalar` without clearing `self` or allocating.
            ///
            /// # Correctness
            ///
            /// Both ciphertexts must have the same length, layout, representation,
            /// and compatible key semantics. Gadget bases and level/row order must
            /// match. Components are consecutive RNS polynomials, each containing
            /// one length-`poly_length` block per modulus in `moduli` order.
            /// `poly_length` and the modulus count must be nonzero, and
            /// `rns_poly_len = poly_length * moduli.len()`. Ciphertext lengths must
            /// be multiples of `rns_poly_len`. `scalar` must have one entry per
            /// modulus in that same order, applied to every ciphertext component.
            /// Input and accumulator values must be canonical residues, and results
            /// remain canonical. Scalar residues must be canonical under their
            /// corresponding moduli.
            ///
            /// # Panics
            ///
            /// Panics when a zero chunk length is used. Other layout requirements
            /// are caller obligations; debug assertions do not provide release validation.
            #[inline]
            pub fn add_mul_scalar_assign<M, A>(
                &mut self,
                rhs: &$cipher<A>,
                scalar: &primus_rns::Residues<impl primus_data::Data<Elem = T>>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[M],
            ) where
                M: Copy + primus_reduce::ReduceMulAddSlice<T>,
                A: primus_data::Data<Elem = T>,
            {
                debug_assert_eq!(scalar.len(), moduli.len(), "RNS scalar count mismatch");
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
                    for (acc, rhs, &scalar, &modulus) in itertools::izip!(
                        acc.chunks_exact_mut(poly_length),
                        rhs.chunks_exact(poly_length),
                        scalar.iter(),
                        moduli
                    ) {
                        modulus.reduce_add_mul_scalar_slice_assign(acc, rhs, scalar);
                    }
                }
            }
        }
        impl<S, T> $cipher<S>
        where
            S: primus_data::Data<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Writes the scalar product into `output`, overwriting all components.
            ///
            /// # Correctness
            ///
            /// Components are stored consecutively; each contains one length-`poly_length`
            /// block per modulus, in `moduli` order. `poly_length` and `moduli.len()`
            /// must be nonzero, `rns_poly_len = poly_length * moduli.len()`, and
            /// ciphertext lengths must be multiples of `rns_poly_len`.
            /// All operands must have equal lengths, the same ordered modulus base,
            /// and the same coefficient or NTT representation.
            /// `scalar` contains one residue per modulus, in the same order.
            /// Values and residues must satisfy each modulus multiplication input range.
            ///
            /// # Panics
            ///
            /// Panics when a zero chunk length is used. Other layout requirements
            /// are caller obligations; debug assertions do not provide release validation.
            #[inline]
            pub fn mul_scalar_to<M, A>(
                &self,
                scalar: &primus_rns::Residues<impl primus_data::Data<Elem = T>>,
                output: &mut $cipher<A>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[M],
            ) where
                M: Copy + primus_reduce::ReduceMulSlice<T>,
                A: primus_data::DataMut<Elem = T>,
            {
                debug_assert_eq!(scalar.len(), moduli.len(), "RNS scalar count mismatch");
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
                    for (input, output, &scalar, &modulus) in itertools::izip!(
                        input.chunks_exact(poly_length),
                        output.chunks_exact_mut(poly_length),
                        scalar.iter(),
                        moduli
                    ) {
                        modulus.reduce_mul_scalar_slice_to(input, scalar, output);
                    }
                }
            }
        }
    };
}
