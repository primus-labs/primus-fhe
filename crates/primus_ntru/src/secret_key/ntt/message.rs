//! Message adapters encode into the output or existing coefficient scratch.

use super::NttNtruSecretKey;
use crate::{NtruParameters, NttNtruCiphertext};
use primus_data::{Data, DataMut};
use primus_encoding::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{Polynomial, PolynomialOwned};
use primus_reduce::FieldContext;

impl<T: FheUint> NttNtruSecretKey<T> {
    /// Encrypts a message polynomial into a newly allocated NTT-domain NTRU ciphertext.
    /// Inherits [`Self::encrypt_message_to`]'s input and transform requirements.
    ///
    /// # Panics
    ///
    /// Inherits [`Self::encrypt_message_to`]'s layout and plaintext-range panic conditions.
    #[must_use]
    pub fn encrypt_message<M, Table, R, A>(
        &self,
        input: &Polynomial<A>,
        params: &NtruParameters<T, M>,
        embedding: PlaintextEmbedding,
        ntt_table: &Table,
        rng: &mut R,
    ) -> NttNtruCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
    {
        let mut output = NttNtruCiphertext::zero(self.poly_length());
        self.encrypt_message_to(input, &mut output, params, embedding, ntt_table, rng);
        output
    }

    /// Encrypts a message polynomial with the selected embedding into `output`.
    /// Both embeddings accept canonical residues in `[0, t)`; centered `t - 1`
    /// represents `-1`. Encoding is added to the sampled coefficient noise in place.
    ///
    /// `input` and `output` have length `N`, with input values in `[0, t)`.
    ///
    /// # Correctness
    ///
    /// Use the key's construction-time NTT roots and evaluation order.
    ///
    /// # Panics
    ///
    /// Panics before sampling on inconsistent key/parameter/table/input/output
    /// lengths or moduli.
    /// A plaintext-codec panic can leave partial output and consume randomness.
    pub fn encrypt_message_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttNtruCiphertext<B>,
        params: &NtruParameters<T, M>,
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
        self.assert_encrypt_compatible(
            output.as_ref().len(),
            params.encryption_parameters(),
            ntt_table,
        );
        assert_eq!(
            input.as_ref().len(),
            self.poly_length(),
            "NTRU message length mismatch"
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

    /// Builds the codec addition after normalizing storage to borrowed views.
    /// Layout/domain checks precede this call; the codec checks message values after
    /// noise sampling, preserving partial-write and RNG-consumption behavior.
    fn encrypt_message_kernel_to<M, Table, R>(
        &self,
        input: Polynomial<&[T]>,
        output: NttNtruCiphertext<&mut [T]>,
        params: &NtruParameters<T, M>,
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
            |coefficients| {
                params.plaintext_codec().add_encode_slice_assign(
                    coefficients,
                    input.as_ref(),
                    embedding,
                );
            },
        );
    }

    /// Decrypts to unsigned plaintext values in `[0, t)`.
    /// Both unsigned and centered embeddings use this decoder.
    /// Inherits [`Self::decrypt_message_to`]'s representation and recovery requirements.
    ///
    /// # Panics
    ///
    /// Inherits [`Self::decrypt_message_to`]'s parameter and layout checks.
    #[must_use]
    pub fn decrypt_message<M, Table, A>(
        &self,
        input: &NttNtruCiphertext<A>,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
    ) -> PolynomialOwned<T>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let mut output = PolynomialOwned::zero(self.poly_length());
        self.decrypt_message_to(input, &mut output, params, ntt_table);
        output
    }

    /// Decrypts into an existing message polynomial, returning canonical `[0, t)` residues.
    /// Inherits [`Self::decrypt_phase_to`]'s representation requirements. Recovering
    /// the original message requires phase error within the codec's decoding margin.
    ///
    /// # Panics
    ///
    /// Panics before writes if the parameter length differs from this key or the
    /// inputs violate [`Self::decrypt_phase_to`]'s compatibility checks.
    pub fn decrypt_message_to<M, Table, A, B>(
        &self,
        input: &NttNtruCiphertext<A>,
        output: &mut Polynomial<B>,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            params.poly_length().get(),
            self.poly_length(),
            "NTRU parameter length mismatch"
        );
        self.decrypt_phase_to(input, output, params.cipher_modulus(), ntt_table);
        params
            .plaintext_codec()
            .decode_slice_assign(output.as_mut());
    }
}
