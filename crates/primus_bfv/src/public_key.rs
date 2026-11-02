use primus_data::{Data, DataMut};
use primus_encoding::PlaintextEmbedding;
use primus_glwe_rns::{
    DcrtGlweCiphertext, DcrtGlweDomain, DcrtGlwePublicKey, DcrtGlwePublicKeyWorkspace,
    DcrtGlweRawPublicKeyEncryptor, RnsDomainError,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{U64DcrtTable, U64NttTable};
use primus_poly::{CrtPolynomial, Polynomial};

use crate::BfvParameters;

/// Prepared BFV public encryption with one reusable ephemeral polynomial.
///
/// Mutable access serializes reuse of its erasing workspace. Independent
/// concurrent operations use separate encryptors while sharing keys/tables.
/// Public-key noise needs its own recovery bound beyond parameter construction.
pub struct BfvPublicKeyEncryptor<'a> {
    raw: DcrtGlweRawPublicKeyEncryptor<'a, u64, BarrettModulus<u64>, U64NttTable>,
    parameters: &'a BfvParameters,
}

impl<'a> BfvPublicKeyEncryptor<'a> {
    /// Checks the numerical domain once and allocates one ephemeral polynomial.
    ///
    /// # Errors
    /// Rejects a different key layout or ordered parameter/table basis. Actual
    /// secret and transform identity remain caller contracts.
    pub fn try_new(
        key: &'a DcrtGlwePublicKey<u64>,
        parameters: &'a BfvParameters,
        table: &'a U64DcrtTable,
    ) -> Result<Self, RnsDomainError<u64>> {
        let domain = DcrtGlweDomain::try_new(
            parameters.encryption_parameters(),
            parameters.base_q(),
            table,
        )?;
        Ok(Self {
            raw: key.try_bind_raw(&domain)?,
            parameters,
        })
    }

    /// Returns the retained workspace geometry and erasure contract.
    #[must_use]
    pub fn workspace(&self) -> &DcrtGlwePublicKeyWorkspace<u64> {
        self.raw.workspace()
    }

    /// Borrows scratch for explicit erasure without releasing its allocation.
    pub fn workspace_mut(&mut self) -> &mut DcrtGlwePublicKeyWorkspace<u64> {
        self.raw.workspace_mut()
    }

    /// Encrypts unscaled CRT plaintext lifts, allocating only the returned ciphertext.
    /// Scaling and input conditions follow [`Self::encrypt_plaintext_crt_to`].
    #[must_use]
    pub fn encrypt_plaintext_crt<R, A>(
        &mut self,
        input: &CrtPolynomial<A>,
        rng: &mut R,
    ) -> DcrtGlweCiphertext<Vec<u64>>
    where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
    {
        let mut output = DcrtGlweCiphertext::zero(self.parameters.rns_glwe_len());
        self.encrypt_plaintext_crt_to(input, &mut output, rng);
        output
    }

    /// Encrypts a complete unscaled coefficient-domain CRT plaintext, without allocation.
    /// Applies delta exactly once before the body's sole NTT. Passing encoded
    /// codec output would scale twice. Each GLWE component still has one NTT.
    ///
    /// # Correctness
    /// Input contains canonical residues in Q order and the intended plaintext
    /// lifts. Public-key/evaluated noise requires a separate recovery bound.
    ///
    /// # Panics
    /// Full layout errors are rejected before sampling/writes. RNG, callback or
    /// transform panics can leave partial output and scratch.
    pub fn encrypt_plaintext_crt_to<R, A, B>(
        &mut self,
        input: &CrtPolynomial<A>,
        output: &mut DcrtGlweCiphertext<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        let parameters = self.parameters;
        assert_eq!(
            input.as_ref().len(),
            parameters.rns_poly_len(),
            "BFV CRT plaintext length mismatch"
        );
        self.raw
            .encrypt_with_components_to(output, rng, |index, polynomial| {
                if index == 1 {
                    polynomial.add_mul_factor_assign(
                        input,
                        parameters.delta_factor_mod_q().as_ref(),
                        parameters.poly_length().get(),
                        parameters.cipher_moduli_value(),
                    );
                }
            });
    }

    /// Encrypts N coefficients in `[0,t)` using unsigned BFV embedding.
    /// No scratch/NTT beyond the shared raw public encryption kernel is added.
    ///
    /// # Panics
    /// Full input/output/workspace geometry is checked before sampling/writes.
    /// Coefficient values are checked by the codec after sampling; codec, RNG or
    /// transform panics can leave partial output and scratch.
    pub fn encrypt_to<R, A, B>(
        &mut self,
        input: &Polynomial<A>,
        output: &mut DcrtGlweCiphertext<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        self.encrypt_coefficients_to(input, output, rng, PlaintextEmbedding::Unsigned);
    }

    /// Encrypts N coefficients using centered embedding with [`Self::encrypt_to`]'s
    /// layout, allocation and panic contract.
    pub fn encrypt_centered_to<R, A, B>(
        &mut self,
        input: &Polynomial<A>,
        output: &mut DcrtGlweCiphertext<B>,
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
        output: &mut DcrtGlweCiphertext<B>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        let parameters = self.parameters;
        assert_eq!(
            input.as_ref().len(),
            parameters.poly_length().get(),
            "BFV plaintext length mismatch"
        );
        self.raw
            .encrypt_with_components_to(output, rng, |index, polynomial| {
                if index == 1 {
                    parameters
                        .codec()
                        .add_encode_coeffs_assign(input, polynomial, embedding);
                }
            });
    }
}
