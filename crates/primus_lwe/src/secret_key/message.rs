//! Message adapters select a codec and embedding without intermediate plaintext buffers.

use crate::batch::{batch_iter, batch_len, check_batch};
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::lwe::{Lwe, LweIter, MultiMsgLwe};
use primus_reduce::RingContext;

use super::LweSecretKey;
use crate::{LweCiphertext, LweParameters, MultiMsgLweCiphertext, PlaintextEmbedding};

impl<T: FheUint> LweSecretKey<T> {
    /// Encodes the message with the selected embedding, then encrypts the encoded residue.
    ///
    /// # Correctness
    ///
    /// The key must satisfy the [type's parameter contract](Self#correctness).
    /// Both embeddings accept residues in `[0,t)`; see
    /// [`RoundedCodec::encode_value`](primus_encoding::RoundedCodec::encode_value).
    ///
    /// # Panics
    ///
    /// Panics before allocating or sampling if the recorded key modulus differs
    /// from `params`, or `message` lies outside `[0,t)`.
    #[must_use]
    #[inline]
    pub fn encrypt_message<R, M>(
        &self,
        message: T,
        params: &LweParameters<T, M>,
        embedding: PlaintextEmbedding,
        rng: &mut R,
    ) -> LweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        self.check_modulus(params.cipher_modulus());
        debug_assert_eq!(self.dimension(), params.dimension().get());

        let plaintext = params.plaintext_codec().encode_value(message, embedding);
        self.as_view().encrypt_encoded(
            plaintext,
            params.cipher_modulus(),
            params.cipher_modulus_uniform_distr(),
            params.noise_distribution(),
            rng,
        )
    }

    /// Encodes a canonical message and overwrites all coefficients of `output`.
    /// No allocation is performed.
    ///
    /// # Correctness
    ///
    /// The key must satisfy the [type's parameter contract](Self#correctness).
    ///
    /// # Panics
    ///
    /// Panics before writing or sampling if the recorded key modulus differs from
    /// `params`, `message` is outside `[0,t)`, or the output length
    /// is not `self.dimension() + 1`. A panicking RNG can leave partial output.
    #[inline]
    pub fn encrypt_message_to<R, M>(
        &self,
        message: T,
        output: &mut Lwe<impl DataMut<Elem = T>>,
        params: &LweParameters<T, M>,
        embedding: PlaintextEmbedding,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        self.check_modulus(params.cipher_modulus());
        debug_assert_eq!(self.dimension(), params.dimension().get());
        let plaintext = params.plaintext_codec().encode_value(message, embedding);
        self.as_view().encrypt_encoded_to(
            plaintext,
            output,
            params.cipher_modulus(),
            params.cipher_modulus_uniform_distr(),
            params.noise_distribution(),
            rng,
        );
    }

    /// Decodes a ciphertext to a canonical message.
    ///
    /// Returns a canonical residue in `[0,t)` for either encryption embedding.
    ///
    /// # Correctness
    ///
    /// The key must satisfy the [type's parameter contract](Self#correctness).
    /// The ciphertext must have dimension `params.dimension().get()` and canonical
    /// coefficients under the same modulus. Recovering the original message
    /// also requires its noise to remain within the codec's decoding margin.
    ///
    /// # Panics
    ///
    /// Panics if the recorded key modulus differs from `params`, the ciphertext
    /// has no body, or its mask length differs from the key length.
    #[must_use]
    #[inline]
    pub fn decrypt_message<M>(
        &self,
        cipher_text: &Lwe<impl Data<Elem = T>>,
        params: &LweParameters<T, M>,
    ) -> T
    where
        M: RingContext<T>,
    {
        let modulus = params.cipher_modulus();

        self.check_modulus(modulus);
        debug_assert_eq!(self.dimension(), params.dimension().get());
        let plaintext = self.as_view().decrypt_phase(cipher_text, modulus);

        params.plaintext_codec().decode_value(plaintext)
    }

    /// Allocates a contiguous batch using unsigned or centered embedding.
    ///
    /// See [`Self::encrypt_message_batch_to`] for contracts. Also panics
    /// if the total storage length overflows.
    #[must_use]
    pub fn encrypt_message_batch<M, R>(
        &self,
        messages: &[T],
        params: &LweParameters<T, M>,
        embedding: PlaintextEmbedding,
        rng: &mut R,
    ) -> Vec<T>
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut output = vec![T::ZERO; batch_len(self.dimension(), messages.len())];
        self.encrypt_message_batch_to(messages, &mut output, params, embedding, rng);
        output
    }

    /// Encodes and encrypts each message directly into its ciphertext.
    ///
    /// No allocation or scratch is needed. Empty batches consume no randomness.
    /// RNG ordering is not guaranteed to match repeated single-message calls.
    /// Both embeddings accept canonical residues in `[0,t)`.
    /// Output contains `messages.len()` consecutive `[mask, body]` chunks of
    /// length `self.dimension() + 1`; empty output is valid for empty messages.
    ///
    /// # Correctness
    ///
    /// The key, modulus and noise must satisfy [`Self::encrypt_message_to`].
    /// The batch count is unrestricted by the LWE dimension.
    ///
    /// # Panics
    ///
    /// Parameter dimension/modulus or output length mismatches, and length overflow,
    /// panic before writing or sampling.
    /// Message range or RNG failures may leave partial output
    /// and may have consumed randomness for earlier messages.
    pub fn encrypt_message_batch_to<M, R>(
        &self,
        messages: &[T],
        output: &mut [T],
        params: &LweParameters<T, M>,
        embedding: PlaintextEmbedding,
        rng: &mut R,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_modulus(params.cipher_modulus());
        assert_eq!(
            params.dimension().get(),
            self.dimension(),
            "LWE batch parameter dimension mismatch"
        );
        check_batch(output, self.dimension(), messages.len());

        let plaintexts = messages
            .iter()
            .map(|&message| params.plaintext_codec().encode_value(message, embedding));
        self.encrypt_batch_iter_to(
            plaintexts,
            output,
            params.cipher_modulus(),
            params.cipher_modulus_uniform_distr(),
            params.noise_distribution(),
            rng,
        );
    }

    /// Decrypts consecutive `[mask, body]` chunks into one allocated message vector.
    /// The correctness conditions of [`Self::decrypt_message_batch_to`] apply.
    ///
    /// # Panics
    ///
    /// Panics if the parameter dimension or modulus differs from the key or
    /// input contains an incomplete ciphertext. Empty input returns an empty vector.
    #[must_use]
    pub fn decrypt_message_batch<M>(&self, input: &[T], params: &LweParameters<T, M>) -> Vec<T>
    where
        M: RingContext<T>,
    {
        self.check_modulus(params.cipher_modulus());
        assert_eq!(
            params.dimension().get(),
            self.dimension(),
            "LWE batch parameter dimension mismatch"
        );
        let inputs = batch_iter(input, self.dimension());
        let codec = params.plaintext_codec();
        self.decrypt_phase_iter(inputs, params.cipher_modulus())
            .map(|phase| codec.decode_value(phase))
            .collect()
    }

    /// Decrypts into an exactly sized message slice without allocating.
    /// Both encryption embeddings decode to canonical residues in `[0,t)`.
    /// Input contains `output.len()` chunks of `self.dimension() + 1` coefficients.
    ///
    /// # Correctness
    ///
    /// Every input ciphertext, the key and parameters must satisfy [`Self::decrypt_message`].
    ///
    /// # Panics
    ///
    /// Parameter dimension/modulus or input/output length mismatches, and length overflow,
    /// panic before writing.
    pub fn decrypt_message_batch_to<M>(
        &self,
        input: &[T],
        output: &mut [T],
        params: &LweParameters<T, M>,
    ) where
        M: RingContext<T>,
    {
        self.check_modulus(params.cipher_modulus());
        assert_eq!(
            params.dimension().get(),
            self.dimension(),
            "LWE batch parameter dimension mismatch"
        );
        let lwe_len = check_batch(input, self.dimension(), output.len());
        let codec = params.plaintext_codec();
        let phases = self.decrypt_phase_iter(LweIter::new(input, lwe_len), params.cipher_modulus());
        for (phase, message) in phases.zip(output) {
            *message = codec.decode_value(phase);
        }
    }

    /// Encrypts multiple messages using the selected plaintext embedding.
    ///
    /// Stores a length-`n` mask followed by `messages.len()` bodies, where
    /// `n = params.dimension().get()`. Body `i` uses the mask rotated right by `i`
    /// with the first `i` coefficients negated. An empty message slice is allowed.
    ///
    /// # Correctness
    ///
    /// The key must satisfy the [type's parameter contract](Self#correctness).
    /// Both embeddings accept canonical messages in `[0,t)`.
    ///
    /// # Panics
    ///
    /// Panics if the recorded key modulus differs from `params`, the message count
    /// exceeds `n`, the storage length overflows, or a message lies outside `[0,t)`.
    #[must_use]
    #[inline]
    pub fn encrypt_message_packed<R, M>(
        &self,
        messages: &[T],
        params: &LweParameters<T, M>,
        embedding: PlaintextEmbedding,
        rng: &mut R,
    ) -> MultiMsgLweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        self.check_modulus(params.cipher_modulus());
        debug_assert_eq!(self.dimension(), params.dimension().get());
        let mut output = super::packed::allocate_packed(params.dimension().get(), messages.len());
        let (_, bodies) = output.a_b_mut(params.dimension().get());
        // Bodies start at zero: encode directly into the final storage before sampling.
        params
            .plaintext_codec()
            .add_encode_slice_assign(bodies, messages, embedding);
        self.encrypt_packed_bodies_assign(&mut output, params.encryption_parameters(), rng);
        output
    }

    /// Decodes a packed ciphertext to one canonical message per body.
    ///
    /// Returns canonical residues in `[0,t)` for either embedding, including an
    /// empty vector when the ciphertext retains no bodies.
    ///
    /// # Correctness
    ///
    /// The key must satisfy the [type's parameter contract](Self#correctness).
    /// The ciphertext must use the mask/body layout of
    /// [`Self::encrypt_message_packed`] and canonical coefficients
    /// under the same modulus. Original messages are recovered only within the
    /// codec's decoding margin.
    ///
    /// # Panics
    ///
    /// Panics if the recorded key modulus differs from `params`, storage is shorter
    /// than the key dimension, or the body count exceeds that dimension.
    /// Debug builds also check the parameter dimension.
    #[must_use]
    #[inline]
    pub fn decrypt_message_packed<M>(
        &self,
        cipher_text: &MultiMsgLwe<impl Data<Elem = T>>,
        params: &LweParameters<T, M>,
    ) -> Vec<T>
    where
        M: RingContext<T>,
    {
        debug_assert_eq!(self.dimension(), params.dimension().get());
        let mut messages = self.decrypt_phase_packed(cipher_text, params.cipher_modulus());
        params.plaintext_codec().decode_slice_assign(&mut messages);
        messages
    }
}
