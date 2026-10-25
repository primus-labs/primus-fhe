//! Injection of already weighted messages into a gadget diagonal.

macro_rules! impl_gadget_diagonal_single_modulus {
    ($cipher:ident, $poly:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Adds an already gadget-weighted plaintext to the diagonal of one level.
            ///
            /// Storage is `[row][level][component][polynomial entry]`. The number
            /// of components equals the number of rows. `level` is
            /// a zero-based storage index; the caller maps it to its gadget weight.
            /// Every diagonal polynomial at this level receives `plaintext`, while
            /// other levels and off-diagonal components remain unchanged.
            ///
            /// # Correctness
            ///
            /// `plaintext` must be one complete nonempty polynomial already multiplied
            /// by the selected gadget weight and encoded in this ciphertext's domain
            /// and scale. This performs neither encoding nor encryption, and allocates
            /// no temporary storage. Adding all levels implements addition of `m*G`
            /// under the caller's gadget convention.
            /// `size` must describe the complete ciphertext and plaintext layouts;
            /// `level` must be less than its decomposition length. The caller must match
            /// the actual buffers to `size` before invoking this operation.
            /// Input residues must be canonical; results remain canonical.
            #[inline]
            pub fn add_gadget_diagonal_assign<M, A>(
                &mut self,
                plaintext: &primus_poly::$poly<A>,
                level: usize,
                size: crate::GadgetSize,
                modulus: M,
            ) where
                A: primus_data::Data<Elem = T>,
                M: Copy + primus_reduce::ReduceAddSlice<T>,
            {
                let glwe_size = size.glwe_size();
                debug_assert!(
                    level < size.level_count().get(),
                    "gadget level is out of range"
                );
                for diagonal in crate::gadget::diagonal_level_mut(
                    self.as_mut(),
                    glwe_size.poly_length().get(),
                    level,
                    glwe_size.glwe_len(),
                    size.glev_len(),
                ) {
                    modulus.reduce_add_slice_assign(diagonal, plaintext.as_ref());
                }
            }
        }
    };
}

#[cfg(feature = "rns")]
macro_rules! impl_gadget_diagonal_multiple_modulus {
    ($cipher:ident, $poly:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Adds an already gadget-weighted plaintext to the diagonal of one level.
            ///
            /// Storage is `[row][level][component][polynomial entry]`. The number
            /// of components equals the number of rows. `level` is
            /// a zero-based storage index; the caller maps it to its gadget weight.
            /// Every diagonal polynomial at this level receives `plaintext`, while
            /// other levels and off-diagonal components remain unchanged.
            ///
            /// # Correctness
            ///
            /// `plaintext` must be one complete nonempty polynomial already multiplied
            /// by the selected gadget weight and encoded in this ciphertext's domain
            /// and scale. This performs neither encoding nor encryption, and allocates
            /// no temporary storage. Adding all levels implements addition of `m*G`
            /// under the caller's gadget convention.
            /// `size` must describe the complete ciphertext and plaintext layouts;
            /// `level` must be less than its decomposition length. The caller must match
            /// the actual buffers to `size` before invoking this operation.
            /// Input residues must be canonical; results remain canonical.
            /// Each polynomial contains one block per modulus, of length
            /// `size.rns_glwe_size().poly_length().get()`, in the same nonempty basis
            /// order as `moduli`. `moduli.len()` must equal the modulus count in `size`.
            #[inline]
            pub fn add_gadget_diagonal_assign<M, A>(
                &mut self,
                plaintext: &primus_poly::$poly<A>,
                level: usize,
                size: crate::RnsGadgetSize,
                moduli: &[M],
            ) where
                A: primus_data::Data<Elem = T>,
                M: Copy + primus_reduce::ReduceAddSlice<T>,
            {
                let glwe_size = size.rns_glwe_size();
                let poly_length = glwe_size.poly_length().get();
                debug_assert!(
                    level < size.level_count().get(),
                    "gadget level is out of range"
                );
                for diagonal in crate::gadget::diagonal_level_mut(
                    self.as_mut(),
                    glwe_size.rns_poly_len(),
                    level,
                    glwe_size.rns_glwe_len(),
                    size.rns_glev_len(),
                ) {
                    for (diagonal, plaintext, &modulus) in itertools::izip!(
                        diagonal.chunks_exact_mut(poly_length),
                        plaintext.as_ref().chunks_exact(poly_length),
                        moduli
                    ) {
                        modulus.reduce_add_slice_assign(diagonal, plaintext);
                    }
                }
            }
        }
    };
}
