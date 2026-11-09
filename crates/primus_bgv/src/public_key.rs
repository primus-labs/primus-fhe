use crate::client::{add_plaintext, sample_scaled_noise, validate_plaintext};
use crate::{BgvCiphertext, BgvClient, BgvContext};
use primus_data::{Data, DataMut};
use primus_glwe_rns::{DcrtGlwePublicKeyWorkspace, RnsDomainError};
use primus_lattice::RnsGlweSize;
use primus_poly::{DcrtPolynomial, Polynomial};
use zeroize::Zeroize;

/// A mismatched BGV public-key basis, geometry or plaintext scale.
#[derive(Debug, thiserror::Error)]
pub enum BgvPublicKeyError {
    /// Geometry or ordered ciphertext moduli differ.
    #[error(transparent)]
    Rns(#[from] RnsDomainError<u64>),
    /// A public key's error is scaled by a different plaintext modulus.
    #[error("BGV public-key plaintext modulus mismatch: expected {expected}, got {actual}")]
    PlainModulus {
        /// Required plaintext modulus.
        expected: u64,
        /// Public-key plaintext modulus.
        actual: u64,
    },
}

/// Native BGV public key `[c0,c1]` with phase `p*e_pk`.
/// Public encryption therefore preserves p-multiple error under the same secret.
pub struct BgvPublicKey {
    ciphertext: BgvCiphertext<Vec<u64>>,
    size: RnsGlweSize,
    moduli: Vec<u64>,
    p: u64,
}
impl BgvPublicKey {
    /// Borrows the public native ciphertext for authenticated serialization.
    /// The payload alone does not identify its NTT/context or recipient secret.
    #[must_use]
    pub fn as_ciphertext(&self) -> BgvCiphertext<&[u64]> {
        BgvCiphertext::new(self.ciphertext.as_ref())
    }

    pub(crate) fn from_collective(
        context: &BgvContext,
        ciphertext: BgvCiphertext<Vec<u64>>,
    ) -> Self {
        Self {
            ciphertext,
            size: context.parameters().size(),
            moduli: context.parameters().base_q().moduli_values().to_vec(),
            p: context.parameters().plain_modulus().value(),
        }
    }

    pub(crate) fn generate<R: rand::Rng + rand::CryptoRng>(
        client: &BgvClient<'_>,
        context: &BgvContext,
        rng: &mut R,
    ) -> Self {
        let mut ciphertext = context.new_ciphertext(0);
        client.encrypt_zeros_at_level_to(&mut ciphertext, 0, rng);
        Self {
            ciphertext,
            size: context.parameters().size(),
            moduli: context.parameters().base_q().moduli_values().to_vec(),
            p: context.parameters().plain_modulus().value(),
        }
    }
    /// Checks public-key polynomial geometry, p and the complete ordered Q basis.
    /// This metadata-only check allocates nothing. Actual recipient identity and
    /// NTT roots/evaluation order remain caller contracts.
    /// # Errors
    /// Rejects different geometry, plaintext modulus or ordered ciphertext basis.
    pub fn validate_context(&self, context: &BgvContext) -> Result<(), BgvPublicKeyError> {
        let parameters = context.parameters();
        let expected = parameters.poly_length().get();
        let actual = self.size.poly_length().get();
        if expected != actual {
            return Err(RnsDomainError::PolynomialLengthMismatch { expected, actual }.into());
        }
        let expected = parameters.base_q().moduli_count();
        let actual = self.moduli.len();
        if expected != actual {
            return Err(RnsDomainError::ModuliCountMismatch { expected, actual }.into());
        }
        for (index, (&expected, &actual)) in parameters
            .base_q()
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
                }
                .into());
            }
        }
        if self.p != parameters.plain_modulus().value() {
            return Err(BgvPublicKeyError::PlainModulus {
                expected: parameters.plain_modulus().value(),
                actual: self.p,
            });
        }
        Ok(())
    }
}

/// Prepared native public encryption with one erasing full-ring ephemeral.
/// No key clone, raw-GLWE conversion or online allocation is introduced.
pub struct BgvPublicKeyEncryptor<'a> {
    key: &'a BgvPublicKey,
    context: &'a BgvContext,
    workspace: DcrtGlwePublicKeyWorkspace<u64>,
}
impl<'a> BgvPublicKeyEncryptor<'a> {
    /// Checks key geometry, ordered Q and p, then allocates one full-ring ephemeral.
    ///
    /// # Errors
    /// Rejects a different layout, Q order or plaintext error scale. Actual secret
    /// and NTT convention remain caller contracts after numerical checks.
    pub fn try_new(
        key: &'a BgvPublicKey,
        context: &'a BgvContext,
    ) -> Result<Self, BgvPublicKeyError> {
        key.validate_context(context)?;
        Ok(Self {
            key,
            context,
            workspace: DcrtGlwePublicKeyWorkspace::new(context.parameters().size()),
        })
    }
    /// Encrypts coefficients, allocating only the returned level-zero ciphertext.
    /// See [`Self::encrypt_to`] for the input, phase and failure contracts.
    #[must_use]
    pub fn encrypt<R, A>(&mut self, input: &Polynomial<A>, rng: &mut R) -> BgvCiphertext<Vec<u64>>
    where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
    {
        let mut output = self.context.new_ciphertext(0);
        self.encrypt_to(input, &mut output, rng);
        output
    }

    /// Encrypts centered lifts, allocating only the returned ciphertext.
    /// See [`Self::encrypt_centered_to`] for the input and phase contracts.
    #[must_use]
    pub fn encrypt_centered<R, A>(
        &mut self,
        input: &Polynomial<A>,
        rng: &mut R,
    ) -> BgvCiphertext<Vec<u64>>
    where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
    {
        let mut output = self.context.new_ciphertext(0);
        self.encrypt_centered_to(input, &mut output, rng);
        output
    }
    /// Encrypts N canonical coefficients with unsigned lifts, allocating nothing.
    ///
    /// The exact phase is `m+p*(e_pk*r+e_0+e_1*s)`. Public ephemeral r uses
    /// exact CBD1 coefficients independent of the chosen secret/error sampler.
    /// # Correctness
    /// Public error must remain in the centered Q recovery interval.
    /// # Panics
    /// Rejects incorrect complete lengths and noncanonical plaintext before RNG
    /// or writes. RNG/transform failure may partially write scratch and output.
    pub fn encrypt_to<R, A, B>(
        &mut self,
        input: &Polynomial<A>,
        output: &mut BgvCiphertext<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        self.encrypt_coefficients_to(input, output, rng, false);
    }
    /// Encrypts centered plaintext lifts; see [`Self::encrypt_to`] for contracts.
    pub fn encrypt_centered_to<R, A, B>(
        &mut self,
        input: &Polynomial<A>,
        output: &mut BgvCiphertext<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        self.encrypt_coefficients_to(input, output, rng, true);
    }
    fn encrypt_coefficients_to<R, A, B>(
        &mut self,
        input: &Polynomial<A>,
        output: &mut BgvCiphertext<B>,
        rng: &mut R,
        centered: bool,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        validate_plaintext(self.context, input.as_ref());
        let parameters = self.context.parameters();
        assert_eq!(
            self.workspace.size(),
            parameters.size(),
            "BGV public workspace shape mismatch"
        );
        let n = parameters.poly_length().get();
        let (mut c0, mut c1) = output.c0_c1_mut(self.context.rns_poly_len(0));
        let sampling = parameters.encryption_parameters();
        let ephemeral = self.workspace.as_mut_slice();
        primus_distr::sample_crt_sparse_ternary_values_to(
            ephemeral,
            n,
            sampling.cipher_moduli_minus_one(),
            rng,
        );
        self.context.table().transform_slice(ephemeral);
        let ephemeral = DcrtPolynomial(&*ephemeral);
        let (pk0, pk1) = self.key.ciphertext.c0_c1(self.context.rns_poly_len(0));
        sample_scaled_noise(self.context, 0, c0.as_mut(), rng);
        add_plaintext(self.context, input.as_ref(), c0.as_mut(), centered);
        self.context.table().transform_slice(c0.as_mut());
        c0.add_mul_assign(&ephemeral, &pk0, n, parameters.base_q().moduli());
        sample_scaled_noise(self.context, 0, c1.as_mut(), rng);
        self.context.table().transform_slice(c1.as_mut());
        c1.add_mul_assign(&ephemeral, &pk1, n, parameters.base_q().moduli());
    }
}

impl Zeroize for BgvPublicKeyEncryptor<'_> {
    /// Erases the ephemeral while retaining its complete prepared allocation.
    fn zeroize(&mut self) {
        self.workspace.zeroize();
    }
}

#[cfg(test)]
mod tests;
