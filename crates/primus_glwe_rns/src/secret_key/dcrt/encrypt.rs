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
        mut output: DcrtGlweCiphertext<&mut [T]>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.parameters;
        let table = self.table;
        let poly_length = parameters.poly_length().get();
        let rns_poly_len = parameters.rns_poly_len();
        let moduli = parameters.cipher_moduli();
        let uniform_distrs = parameters.cipher_moduli_uniform_distr();
        let (a, mut b) = output.a_b_mut(rns_poly_len);

        primus_distr::sample_crt_gaussian_values_to(
            b.as_mut(),
            poly_length,
            parameters.cipher_moduli_value(),
            parameters.noise_distribution(),
            rng,
        );
        match message {
            DcrtEncryptionMessage::PlaintextCrt(message) => {
                CrtPolynomial(b.as_mut()).add_mul_factor_assign(
                    &message,
                    parameters.delta_factor_mod_q().as_ref(),
                    poly_length,
                    parameters.cipher_moduli_value(),
                );
            }
            DcrtEncryptionMessage::Plaintext {
                polynomial,
                embedding,
            } => {
                parameters.codec().add_encode_coeffs_assign(
                    &polynomial,
                    &mut CrtPolynomial(b.as_mut()),
                    embedding,
                );
            }
            DcrtEncryptionMessage::Zero => {}
        }
        table.transform_slice(b.as_mut());

        self.key.iter_dcrt_poly().zip(a).for_each(|(si, mut ai)| {
            primus_distr::sample_crt_uniform_values_to(
                ai.as_mut(),
                poly_length,
                uniform_distrs,
                rng,
            );
            b.add_mul_assign(&ai, &si, poly_length, moduli);
        });
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
