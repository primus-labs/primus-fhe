//! Message adapters for NTT public-key encryption.

use super::{NttGlwePublicEncryptWorkspace, NttGlwePublicKey};
use crate::{GlweParameters, NttGlweCiphertext, PlaintextEmbedding};
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_reduce::FieldContext;

impl<S, T> NttGlwePublicKey<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Encrypts a polynomial into a newly allocated NTT-domain ciphertext.
    ///
    /// # Panics
    ///
    /// Inherits [`Self::encrypt_message_to`]'s layout and plaintext-range panic conditions.
    #[must_use]
    pub fn encrypt_message<M, Table, R, A>(
        &self,
        input: &Polynomial<A>,
        params: &GlweParameters<T, M>,
        embedding: PlaintextEmbedding,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
    ) -> NttGlweCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
    {
        let mut output = NttGlweCiphertext::zero(params.glwe_len());
        self.encrypt_message_to(input, &mut output, params, embedding, ntt, rng, workspace);
        output
    }

    /// Encrypts a message polynomial with the selected embedding into `output` without allocating.
    /// Both embeddings accept canonical residues in `[0, t)`; centered `t - 1`
    /// represents `-1`. Encoding is added to the sampled body noise in place.
    ///
    /// `workspace` holds one reusable ephemeral polynomial of `params.poly_length().get()`
    /// coefficients. It may be reused across keys with the same polynomial length.
    ///
    /// # Panics
    ///
    /// Panics if key/output/message/workspace lengths differ from `params`, or the table
    /// has a different polynomial length or modulus. Checks precede output writes.
    ///
    /// Also panics if any plaintext coefficient is outside `[0, t)`. That check
    /// occurs in the codec and may leave partial output or consume randomness.
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit embedding and encryption resources"
    )]
    pub fn encrypt_message_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        embedding: PlaintextEmbedding,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            input.as_ref().len(),
            params.poly_length().get(),
            "GLWE message length mismatch"
        );
        NttGlwePublicKey::from(self.key.as_view()).encrypt_message_kernel_to(
            input.as_view(),
            output.as_mut_view(),
            params,
            embedding,
            ntt,
            rng,
            workspace,
        );
    }
}

impl<T: FheUint> NttGlwePublicKey<&[T]> {
    /// Input length was checked at the public entry. Check the ordinary key/table
    /// layout here; the shared kernel checks output and remaining resources before
    /// sampling. The codec runs afterward.
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit message embedding and encryption resources"
    )]
    fn encrypt_message_kernel_to<M, Table, R>(
        &self,
        input: Polynomial<&[T]>,
        output: NttGlweCiphertext<&mut [T]>,
        params: &GlweParameters<T, M>,
        embedding: PlaintextEmbedding,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        assert_eq!(
            self.key.as_ref().len(),
            params.glwe_len(),
            "GLWE public key layout mismatch"
        );
        assert_eq!(
            ntt.poly_length(),
            params.poly_length(),
            "NTT polynomial length mismatch"
        );
        self.encrypt_kernel_to(
            output,
            params.encryption_parameters(),
            ntt,
            rng,
            workspace,
            |body| {
                params
                    .plaintext_codec()
                    .add_encode_slice_assign(body, input.as_ref(), embedding);
            },
        );
    }
}
