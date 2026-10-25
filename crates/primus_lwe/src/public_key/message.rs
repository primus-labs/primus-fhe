//! Message adapters select a codec and embedding without intermediate plaintext buffers.

use primus_data::DataMut;
use primus_integer::FheUint;
use primus_lattice::lwe::Lwe;
use primus_reduce::RingContext;

use super::LwePublicKey;
use crate::batch::{batch_len, check_batch};
use crate::{LweCiphertext, LweParameters, PlaintextEmbedding};

impl<T: FheUint> LwePublicKey<T> {
    /// Encodes a canonical message, then encrypts the encoded residue.
    ///
    /// Both embeddings accept unsigned residues in `[0,t)`; under centered
    /// embedding, `t - 1` represents `-1`.
    ///
    /// # Correctness
    ///
    /// The [type's security and noise requirements](Self#correctness) apply.
    /// The plaintext codec must match the decoder's encoding parameters.
    ///
    /// # Panics
    ///
    /// Panics before allocating or sampling if the parameter dimension or
    /// modulus differs from the key's, or the message violates
    /// [`RoundedCodec::encode_value`](primus_encoding::RoundedCodec::encode_value).
    #[must_use]
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
        assert_eq!(
            params.dimension(),
            self.dimension,
            "LWE public-key parameter dimension mismatch"
        );
        let plaintext = params.plaintext_codec().encode_value(message, embedding);
        self.encrypt_encoded(
            plaintext,
            params.cipher_modulus(),
            params.noise_distribution(),
            rng,
        )
    }

    /// Encodes a message and overwrites all output coefficients without allocating.
    ///
    /// # Correctness
    ///
    /// The correctness conditions of [`Self::encrypt_message`] apply.
    ///
    /// # Panics
    ///
    /// Panics before writing or sampling under the conditions of
    /// [`Self::encrypt_message`], or if the output length is not
    /// `self.dimension() + 1`. A panicking RNG can leave partial output.
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
        assert_eq!(
            params.dimension(),
            self.dimension,
            "LWE public-key parameter dimension mismatch"
        );
        let plaintext = params.plaintext_codec().encode_value(message, embedding);
        self.encrypt_encoded_to(
            plaintext,
            output,
            params.cipher_modulus(),
            params.noise_distribution(),
            rng,
        );
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
        let mut output = vec![T::ZERO; batch_len(self.dimension().get(), messages.len())];
        self.encrypt_message_batch_to(messages, &mut output, params, embedding, rng);
        output
    }

    /// Encodes and initializes messages within each tile, then accumulates public-key rows.
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
    /// Parameter dimension, output length, or modulus mismatches, and length
    /// overflow, panic before writing or sampling.
    /// Message range or RNG failures may leave partial output
    /// and consumed randomness. An interrupted tile may contain only noise and
    /// encoded messages, without the public-key row contributions.
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
        assert_eq!(
            params.dimension(),
            self.dimension(),
            "LWE batch parameter dimension mismatch"
        );
        check_batch(output, self.dimension().get(), messages.len());
        self.check_modulus(params.cipher_modulus());
        let plaintexts = messages
            .iter()
            .map(|&message| params.plaintext_codec().encode_value(message, embedding));
        self.encrypt_batch_iter_to(
            plaintexts,
            output,
            params.cipher_modulus(),
            params.noise_distribution(),
            rng,
        );
    }
}
