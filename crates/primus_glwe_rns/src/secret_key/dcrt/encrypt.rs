//! Ordinary DCRT encryption with CRT, unsigned or centered BFV messages.

use primus_data::{Data, DataMut};
use primus_encoding::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{CrtPolynomial, Polynomial};
use primus_reduce::FieldContext;

use super::DcrtGlweSecretKeyContext;
use crate::DcrtGlweCiphertext;

impl<T, M, Table> DcrtGlweSecretKeyContext<'_, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Encrypts one coefficient-domain CRT plaintext polynomial into `output`.
    ///
    /// The message contains unscaled plaintext lifts reduced into each `[0, q_i)`,
    /// in coefficient-domain CRT layout. This method applies `floor(Q/t)` scaling;
    /// passing the already-scaled output of [`crate::BfvRnsCodec::encode_coeffs_to`]
    /// would apply the scale twice.
    pub fn encrypt_plaintext_crt_to<R, A, B>(
        &self,
        input: &CrtPolynomial<A>,
        output: &mut DcrtGlweCiphertext<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.encrypt_kernel_to(
            DcrtEncryptionMessage::PlaintextCrt(input.as_view()),
            output.as_mut_view(),
            rng,
        );
    }

    /// Encrypts N canonical plaintext values in `[0,t)` using unsigned embedding.
    /// Overwrites a complete GLWE output in the bound RNS layout.
    pub fn encrypt_to<R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut DcrtGlweCiphertext<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.encrypt_kernel_to(
            DcrtEncryptionMessage::Plaintext {
                polynomial: input.as_view(),
                embedding: PlaintextEmbedding::Unsigned,
            },
            output.as_mut_view(),
            rng,
        );
    }

    /// Encrypts N canonical plaintext values in `[0,t)` using centered embedding.
    /// Overwrites a complete GLWE output in the bound RNS layout.
    pub fn encrypt_centered_to<R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut DcrtGlweCiphertext<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.encrypt_kernel_to(
            DcrtEncryptionMessage::Plaintext {
                polynomial: input.as_view(),
                embedding: PlaintextEmbedding::Centered,
            },
            output.as_mut_view(),
            rng,
        );
    }

    /// Encrypts zero into an existing DCRT GLWE allocation.
    ///
    /// The output is overwritten and uses the bound parameters' full GLWE layout.
    pub fn encrypt_zeros_to<R, A>(&self, output: &mut DcrtGlweCiphertext<A>, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
        A: DataMut<Elem = T>,
    {
        self.encrypt_kernel_to(DcrtEncryptionMessage::Zero, output.as_mut_view(), rng);
    }

    /// Samples coefficient noise, injects the BFV message, then transforms the body.
    /// Uniform masks are sampled in DCRT form afterward, in secret-component order.
    /// The context has bound the key/parameters/table numerical domain. Message
    /// and output layouts and NTT identity remain caller contracts.
    fn encrypt_kernel_to<R>(
        &self,
        message: DcrtEncryptionMessage<'_, T>,
        output: DcrtGlweCiphertext<&mut [T]>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.parameters;
        let poly_length = parameters.poly_length().get();
        super::raw::encrypt_kernel_to(
            self.key,
            parameters.encryption_parameters(),
            parameters.base_q(),
            self.table,
            output,
            rng,
            |body| match message {
                DcrtEncryptionMessage::PlaintextCrt(message) => body.add_mul_factor_assign(
                    &message,
                    parameters.delta_factor_mod_q().as_ref(),
                    poly_length,
                    parameters.cipher_moduli_value(),
                ),
                DcrtEncryptionMessage::Plaintext {
                    polynomial,
                    embedding,
                } => parameters
                    .codec()
                    .add_encode_coeffs_assign(&polynomial, body, embedding),
                DcrtEncryptionMessage::Zero => {}
            },
        );
    }
}

/// Borrowed message modes for the coefficient body of ordinary DCRT encryption.
/// CRT input contains unscaled plaintext lifts; raw plaintext uses the requested
/// embedding. Both receive BFV scaling before the forward transform.
enum DcrtEncryptionMessage<'a, T: FheUint> {
    PlaintextCrt(CrtPolynomial<&'a [T]>),
    Plaintext {
        polynomial: Polynomial<&'a [T]>,
        embedding: PlaintextEmbedding,
    },
    Zero,
}
