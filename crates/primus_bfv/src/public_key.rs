use primus_data::{Data, DataMut};
use primus_encoding::PlaintextEmbedding;
use primus_glwe_rns::{DcrtGlwePublicKeyWorkspace, RnsDomainError};
use primus_lattice::RnsGlweSize;
use primus_poly::{CrtPolynomial, DcrtPolynomial, Polynomial};
use zeroize::Zeroize;

use crate::secret_key::BfvSecretKeyContext;
use crate::{BfvCiphertext, BfvContext, BfvParameters};

/// Rejected native BFV public-key provenance or numerical geometry.
#[derive(Debug, thiserror::Error)]
pub enum BfvPublicKeyError {
    /// The key belongs to another local context owner.
    #[error("BFV public key context provenance mismatch")]
    ContextMismatch,
    /// The key's numerical geometry differs from the context.
    #[error(transparent)]
    Parameters(#[from] RnsDomainError<u64>),
}

/// A native BFV public key, represented by a zero encryption `[c0,c1]`.
/// Its phase under the generating secret is `c0+c1*s=e`.
#[derive(Clone)]
pub struct BfvPublicKey {
    ciphertext: BfvCiphertext<Vec<u64>>,
    size: RnsGlweSize,
    moduli: Vec<u64>,
}

impl BfvPublicKey {
    /// Canonical native public zero-encryption payload `[c0,c1]` for authenticated transport or binding.
    #[must_use]
    pub fn as_residues(&self) -> &[u64] {
        self.ciphertext.as_ref()
    }

    /// Borrows the public native zero encryption, with no private secret or evaluation columns.
    #[must_use]
    pub fn as_ciphertext(&self) -> BfvCiphertext<&[u64]> {
        self.ciphertext.as_view()
    }

    /// Generates a native public key using an already checked private binding.
    /// Allocation is confined to persistent key storage and its basis metadata.
    #[must_use]
    pub fn new<R: rand::Rng + rand::CryptoRng>(
        context: &BfvSecretKeyContext<'_>,
        rng: &mut R,
    ) -> Self {
        let parameters = context.parameters();
        let mut ciphertext = context.context().new_ciphertext(0);
        context.encrypt_zeros_to(&mut ciphertext, rng);
        Self {
            ciphertext,
            size: parameters.size(),
            moduli: parameters.codec().moduli_values().to_vec(),
        }
    }

    pub(crate) fn from_collective(context: &crate::BfvContext, coefficients: Vec<u64>) -> Self {
        Self {
            ciphertext: BfvCiphertext::bound(coefficients, context, 0),
            size: context.parameters().size(),
            moduli: context.parameters().codec().moduli_values().to_vec(),
        }
    }

    fn validate(&self, parameters: &BfvParameters) -> Result<(), RnsDomainError<u64>> {
        let expected = parameters.poly_length().get();
        let actual = self.size.poly_length().get();
        if expected != actual {
            return Err(RnsDomainError::PolynomialLengthMismatch { expected, actual });
        }
        let expected = parameters.size().moduli_count();
        let actual = self.moduli.len();
        if expected != actual {
            return Err(RnsDomainError::ModuliCountMismatch { expected, actual });
        }
        for (index, (&expected, &actual)) in parameters
            .codec()
            .moduli_values()
            .iter()
            .zip(&self.moduli)
            .enumerate()
        {
            if expected != actual {
                return Err(RnsDomainError::ModulusOrderMismatch {
                    index,
                    expected,
                    actual,
                });
            }
        }
        Ok(())
    }
}

/// Prepared native BFV public encryption with one reusable ephemeral polynomial.
///
/// Mutable access serializes reuse of its erasing workspace. Independent
/// concurrent operations share keys/parameters/tables with separate encryptors.
/// Public-key noise needs its own recovery bound beyond parameter construction.
/// [`Zeroize::zeroize`] erases ephemeral scratch without releasing its allocation.
pub struct BfvPublicKeyEncryptor<'a> {
    key: &'a BfvPublicKey,
    context: &'a BfvContext,
    workspace: DcrtGlwePublicKeyWorkspace<u64>,
}

impl<'a> BfvPublicKeyEncryptor<'a> {
    /// Checks a key against the prepared context, then allocates one ephemeral.
    ///
    /// # Errors
    /// Rejects a different local generating context or numerical key geometry.
    /// Actual secret identity and complete noise bounds remain caller contracts.
    pub(crate) fn try_new(
        key: &'a BfvPublicKey,
        context: &'a BfvContext,
    ) -> Result<Self, BfvPublicKeyError> {
        let parameters = context.parameters();
        let binding = key
            .ciphertext
            .binding
            .as_ref()
            .ok_or(BfvPublicKeyError::ContextMismatch)?;
        if binding.validate(context, 0).is_err() {
            // Preserve precise diagnostics for independently composed resources;
            // the ordinary same-owner path needs no repeated basis scan.
            key.validate(parameters)?;
            return Err(BfvPublicKeyError::ContextMismatch);
        }
        Ok(Self {
            key,
            context,
            workspace: DcrtGlwePublicKeyWorkspace::new(parameters.size()),
        })
    }

    /// Encrypts N canonical coefficients in `[0,t)`, allocating the returned ciphertext.
    /// Uses unsigned embedding and the pre-sampling input checks of [`Self::encrypt_to`].
    #[must_use]
    pub fn encrypt<R, A>(&mut self, input: &Polynomial<A>, rng: &mut R) -> BfvCiphertext<Vec<u64>>
    where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
    {
        let mut output = self.context.new_ciphertext(0);
        self.encrypt_to(input, &mut output, rng);
        output
    }

    /// Encrypts N canonical coefficients with centered embedding, allocating the result.
    /// Input and panic conditions are [`Self::encrypt_to`]'s.
    #[must_use]
    pub fn encrypt_centered<R, A>(
        &mut self,
        input: &Polynomial<A>,
        rng: &mut R,
    ) -> BfvCiphertext<Vec<u64>>
    where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
    {
        let mut output = self.context.new_ciphertext(0);
        self.encrypt_centered_to(input, &mut output, rng);
        output
    }

    /// Encrypts coefficient-domain **unscaled** CRT lifts, applying delta once.
    /// No allocation or extra NTT is introduced. Encoded codec output must use
    /// [`Self::encrypt_encoded_crt_to`] instead, to avoid applying delta twice.
    ///
    /// # Correctness
    /// Input is canonical in parameter Q order and contains intended plaintext
    /// lifts. Public-key/evaluated noise needs a separate complete recovery bound.
    ///
    /// # Panics
    /// Recorded output context/level conflicts and incorrect complete lengths
    /// are rejected before sampling/writes. RNG,
    /// callback or transform panics may leave partial output/scratch.
    pub fn encrypt_plaintext_lift_crt_to<R, A, B>(
        &mut self,
        input: &CrtPolynomial<A>,
        output: &mut BfvCiphertext<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        let parameters = self.context.parameters();
        assert_eq!(
            input.as_ref().len(),
            parameters.size().rns_poly_len(),
            "BFV CRT plaintext length mismatch"
        );
        self.encrypt_with_c0_to(output, rng, |c0| {
            c0.add_mul_factor_assign(
                input,
                parameters.codec().delta_factor_mod_q().as_ref(),
                parameters.poly_length().get(),
                parameters.codec().moduli_values(),
            );
        });
    }

    /// Encrypts N canonical coefficients in `[0,t)` with unsigned embedding.
    /// Encoding is fused before c0's single NTT; no temporary storage is allocated.
    ///
    /// # Panics
    /// Recorded output context/level conflicts, incorrect complete lengths and
    /// noncanonical coefficients are rejected
    /// before sampling or writes. Codec/RNG/NTT panics may leave partial output
    /// and scratch.
    pub fn encrypt_to<R, A, B>(
        &mut self,
        input: &Polynomial<A>,
        output: &mut BfvCiphertext<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        self.encrypt_coefficients_to(input, output, rng, PlaintextEmbedding::Unsigned);
    }

    /// Encrypts N coefficients with centered embedding and [`Self::encrypt_to`]'s contract.
    pub fn encrypt_centered_to<R, A, B>(
        &mut self,
        input: &Polynomial<A>,
        output: &mut BfvCiphertext<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        self.encrypt_coefficients_to(input, output, rng, PlaintextEmbedding::Centered);
    }

    fn encrypt_coefficients_to<R, A, B>(
        &mut self,
        input: &Polynomial<A>,
        output: &mut BfvCiphertext<B>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        let parameters = self.context.parameters();
        assert_eq!(
            input.as_ref().len(),
            parameters.poly_length().get(),
            "BFV plaintext length mismatch"
        );
        assert!(
            input.as_ref().iter().all(|&x| x < parameters.codec().t()),
            "BFV plaintext coefficient is not canonical"
        );
        self.encrypt_with_c0_to(output, rng, |c0| {
            parameters
                .codec()
                .add_encode_coeffs_assign(input, c0, embedding)
        });
    }

    /// Encrypts an already-scaled coefficient CRT phase without another delta.
    /// Canonical residues and Q order are caller contracts. Geometry/panic
    /// conditions are [`Self::encrypt_plaintext_lift_crt_to`]'s.
    pub fn encrypt_encoded_crt_to<R, A, B>(
        &mut self,
        input: &CrtPolynomial<A>,
        output: &mut BfvCiphertext<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        let parameters = self.context.parameters();
        assert_eq!(
            input.as_ref().len(),
            parameters.size().rns_poly_len(),
            "BFV encoded phase length mismatch"
        );
        self.encrypt_with_c0_to(output, rng, |c0| {
            c0.add_assign(
                input,
                parameters.poly_length().get(),
                parameters.base_q().moduli(),
            )
        });
    }

    fn encrypt_with_c0_to<R, B>(
        &mut self,
        output: &mut BfvCiphertext<B>,
        rng: &mut R,
        inject: impl FnOnce(&mut CrtPolynomial<&mut [u64]>),
    ) where
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = u64>,
    {
        output.check_binding(self.context, 0);
        let parameters = self.context.parameters();
        let n = parameters.poly_length().get();
        let length = parameters.size().rns_poly_len();
        let (mut c0, mut c1) = output.c0_c1_mut(length);
        let ephemeral = self.workspace.as_mut_slice();
        let sampling = parameters.encryption_parameters();
        primus_distr::sample_crt_sparse_ternary_values_to(
            ephemeral,
            n,
            sampling.cipher_moduli_minus_one(),
            rng,
        );
        self.context.table().transform_slice(ephemeral);
        let ephemeral = DcrtPolynomial(&*ephemeral);
        let (pk0, pk1) = self.key.ciphertext.c0_c1(length);
        sampling.sample_noise_to(c0.as_mut(), parameters.codec().moduli_values(), rng);
        inject(&mut CrtPolynomial(c0.as_mut()));
        self.context.table().transform_slice(c0.as_mut());
        c0.add_mul_assign(&ephemeral, &pk0, n, parameters.base_q().moduli());
        sampling.sample_noise_to(c1.as_mut(), parameters.codec().moduli_values(), rng);
        self.context.table().transform_slice(c1.as_mut());
        c1.add_mul_assign(&ephemeral, &pk1, n, parameters.base_q().moduli());
    }
}

impl Zeroize for BfvPublicKeyEncryptor<'_> {
    fn zeroize(&mut self) {
        self.workspace.zeroize();
    }
}

#[cfg(test)]
mod tests;

mod persistence;
