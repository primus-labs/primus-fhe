//! Message adapters encode into the final body or existing coefficient scratch.

use super::NttGlweSecretKey;
use crate::{GlweCiphertext, GlweParameters, NttGlweCiphertext, PlaintextEmbedding};
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{Polynomial, PolynomialOwned};
use primus_reduce::FieldContext;

impl<T: FheUint> NttGlweSecretKey<T> {
    /// Encrypts a message polynomial into a newly allocated ciphertext.
    /// Uses the same embedding and contracts as [`Self::encrypt_message_to`].
    ///
    /// # Panics
    ///
    /// Inherits the domain, layout and plaintext-range panic conditions of [`Self::encrypt_message_to`].
    #[must_use]
    pub fn encrypt_message<M, Table, R, A>(
        &self,
        input: &Polynomial<A>,
        params: &GlweParameters<T, M>,
        embedding: PlaintextEmbedding,
        ntt_table: &Table,
        rng: &mut R,
    ) -> NttGlweCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
    {
        let mut output = NttGlweCiphertext::zero(self.size.glwe_len());
        self.encrypt_message_to(input, &mut output, params, embedding, ntt_table, rng);
        output
    }

    /// Encrypts a polynomial message into an NTT-domain GLWE ciphertext.
    /// Both embeddings accept canonical residues in `[0, t)`; centered `t - 1`
    /// represents `-1`. Encoding is added to the sampled body noise in place.
    ///
    /// # Panics
    ///
    /// Panics if the key/parameter/table moduli, layouts, message length,
    /// or output length are incompatible. Compatibility is checked before
    /// writing the ciphertext.
    ///
    /// Also panics if any plaintext coefficient is outside `[0, t)`. That check
    /// occurs in the codec and may leave partial output or consume randomness.
    pub fn encrypt_message_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        embedding: PlaintextEmbedding,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(self.size, params.size(), "GLWE parameter layout mismatch");
        self.assert_encrypt_compatible(
            output.as_ref().len(),
            params.encryption_parameters(),
            ntt_table,
        );
        assert_eq!(
            input.as_ref().len(),
            self.poly_length().get(),
            "GLWE message length mismatch"
        );
        self.encrypt_message_kernel_to(
            input.as_view(),
            output.as_mut_view(),
            params,
            embedding,
            ntt_table,
            rng,
        );
    }

    /// Builds the plaintext body addition after storage has been normalized to views.
    /// The caller has validated all layouts/resources; plaintext range checks still
    /// run in the codec after noise sampling, preserving partial-write/RNG behavior.
    fn encrypt_message_kernel_to<M, Table, R>(
        &self,
        input: Polynomial<&[T]>,
        output: NttGlweCiphertext<&mut [T]>,
        params: &GlweParameters<T, M>,
        embedding: PlaintextEmbedding,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.encrypt_kernel_to(
            output,
            params.encryption_parameters(),
            ntt_table,
            rng,
            |body| {
                params
                    .plaintext_codec()
                    .add_encode_slice_assign(body, input.as_ref(), embedding);
            },
        );
    }

    /// Decrypts an NTT GLWE ciphertext into a newly allocated plaintext polynomial.
    /// Inherits [`Self::decrypt_phase_to`]'s representation requirements.
    ///
    /// # Panics
    ///
    /// Panics if the parameter layout differs from this key or the inputs
    /// violate [`Self::decrypt_phase_to`]'s compatibility checks.
    #[must_use]
    pub fn decrypt_message<M, Table, A>(
        &self,
        input: &NttGlweCiphertext<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
    ) -> PolynomialOwned<T>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let mut output = PolynomialOwned::zero(self.size.poly_length().get());
        self.decrypt_message_to(input, &mut output, params, ntt_table);
        output
    }

    /// Decrypts an NTT GLWE ciphertext into `output`.
    /// Returns canonical residues in `[0, t)` for either encryption embedding.
    /// Recovering the original message requires phase noise within the codec margin.
    ///
    /// Inherits [`Self::decrypt_phase_to`]'s representation requirements. The ciphertext
    /// has `params.glwe_len()` values; output has `params.poly_length().get()` values.
    ///
    /// # Panics
    ///
    /// Panics if the parameter layout differs from this key or the inputs
    /// violate [`Self::decrypt_phase_to`]'s compatibility checks.
    pub fn decrypt_message_to<M, Table, A, B>(
        &self,
        input: &NttGlweCiphertext<A>,
        output: &mut Polynomial<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(self.size, params.size(), "GLWE parameter layout mismatch");
        self.decrypt_phase_to(input, output, params.cipher_modulus(), ntt_table);

        params
            .plaintext_codec()
            .decode_slice_assign(output.as_mut());
    }

    /// Encrypts N message coefficients in `[0, t)` into a coefficient GLWE.
    /// Both embeddings use the same message residues as [`Self::encrypt_message_to`].
    /// Overwrites the entire output without allocating or transforming the body
    /// forward. With the same RNG state, this produces exactly the ciphertext
    /// obtained by [`Self::encrypt_message_to`] followed by an inverse NTT.
    ///
    /// `scratch` has exactly N elements and needs no initialization. It retains
    /// secret-dependent products; its owner is responsible for erasure, e.g. by
    /// storing it in a [`zeroize::Zeroizing`] buffer.
    ///
    /// # Correctness
    ///
    /// The table must use this key's NTT roots and evaluation order.
    ///
    /// # Panics
    ///
    /// Layout, key/parameter/table moduli, table length and scratch length are checked
    /// before sampling or writes. An out-of-range plaintext, RNG or transform panic
    /// may consume randomness and leave partial output or scratch.
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit embedding and encryption resources"
    )]
    pub fn encrypt_message_coeff_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut GlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        embedding: PlaintextEmbedding,
        ntt_table: &Table,
        rng: &mut R,
        scratch: &mut [T],
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(self.size, params.size(), "GLWE parameter layout mismatch");
        let modulus = params.cipher_modulus();
        self.assert_coeff_compatible(
            input.as_ref().len(),
            output.as_ref().len(),
            scratch.len(),
            modulus,
            ntt_table,
        );
        self.encrypt_message_coeff_kernel_to(
            input.as_view(),
            output.as_mut_view(),
            params,
            embedding,
            ntt_table,
            rng,
            scratch,
        );
    }

    /// Constructs the message closure with concrete views after the public
    /// boundary validates key/table/layouts and the exact N-coefficient scratch.
    #[expect(
        clippy::too_many_arguments,
        reason = "message embedding and coefficient scratch"
    )]
    fn encrypt_message_coeff_kernel_to<M, Table, R>(
        &self,
        input: Polynomial<&[T]>,
        output: GlweCiphertext<&mut [T]>,
        params: &GlweParameters<T, M>,
        embedding: PlaintextEmbedding,
        ntt_table: &Table,
        rng: &mut R,
        scratch: &mut [T],
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.encrypt_coeff_kernel_to(
            output,
            params.encryption_parameters(),
            ntt_table,
            rng,
            scratch,
            |body| {
                params
                    .plaintext_codec()
                    .add_encode_slice_assign(body, input.as_ref(), embedding);
            },
        );
    }

    /// Decodes a coefficient GLWE into N unsigned coefficients in `[0, t)`.
    /// Reuses `output` and the N-element `scratch` without allocating.
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::decrypt_phase_coeff_to`]'s requirements. The ciphertext must use
    /// the parameter codec and this secret, with noise within the decoding margin.
    ///
    /// # Panics
    ///
    /// Panics if the parameter layout differs from this key; otherwise inherits
    /// [`Self::decrypt_phase_coeff_to`]'s panic conditions.
    pub fn decrypt_message_coeff_to<M, Table, A, B>(
        &self,
        input: &GlweCiphertext<A>,
        output: &mut Polynomial<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        scratch: &mut [T],
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(self.size, params.size(), "GLWE parameter layout mismatch");
        self.decrypt_phase_coeff_to(input, output, params.cipher_modulus(), ntt_table, scratch);
        params
            .plaintext_codec()
            .decode_slice_assign(output.as_mut());
    }
}
