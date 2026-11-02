use primus_data::{Data, DataMut};
use primus_encoding::PlaintextEmbedding;
use primus_glwe_rns::{
    DcrtGlweCiphertext, DcrtGlweDomain, DcrtGlweRawSecretKeyContext, DcrtGlweSecretKey,
    RnsDomainError,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{U64DcrtTable, U64NttTable};
use primus_poly::{CrtPolynomial, DcrtPolynomial, Polynomial, PolynomialOwned};

use crate::{BfvDecryptWorkspace, BfvParameters};

/// A secret key bound to rank-one BFV parameters and their ordered NTT table.
///
/// Binding checks geometry and numerical basis/table order without allocating
/// or cloning the key. Matching numbers do not establish actual secret identity,
/// NTT root/evaluation identity or evaluated ciphertext noise margin.
pub struct BfvSecretKeyContext<'a> {
    raw: DcrtGlweRawSecretKeyContext<'a, u64, BarrettModulus<u64>, U64NttTable>,
    parameters: &'a BfvParameters,
    table: &'a U64DcrtTable,
}

impl<'a> BfvSecretKeyContext<'a> {
    /// Binds one compatible secret, BFV parameter set and transform table.
    ///
    /// # Errors
    /// Rejects different key geometry or ordered parameter/table moduli.
    pub fn try_new(
        key: &'a DcrtGlweSecretKey<u64>,
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
            table,
        })
    }

    /// Encrypts N coefficients in `[0,t)` using unsigned BFV embedding.
    ///
    /// Applies delta exactly once, adding the encoding to coefficient noise
    /// before the body's sole forward NTT. No scratch allocation occurs.
    ///
    /// # Panics
    /// Complete input/output lengths are checked before sampling or writes.
    /// Invalid coefficient values are rejected by the codec after noise sampling;
    /// codec, RNG or transform panics can leave partial output.
    pub fn encrypt_to<R, A, B>(
        &self,
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

    /// Encrypts N coefficients in `[0,t)` using centered BFV embedding.
    /// The layout, allocation and panic contract is [`Self::encrypt_to`]'s.
    pub fn encrypt_centered_to<R, A, B>(
        &self,
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
        &self,
        input: &Polynomial<A>,
        output: &mut DcrtGlweCiphertext<B>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        assert_eq!(
            input.as_ref().len(),
            self.parameters.poly_length().get(),
            "BFV plaintext length mismatch"
        );
        self.raw.encrypt_with_body_to(output, rng, |body| {
            self.parameters
                .codec()
                .add_encode_coeffs_assign(input, body, embedding);
        });
    }

    /// Encrypts one complete CRT polynomial of unscaled plaintext lifts.
    ///
    /// Canonical coefficient residues use the parameter Q order. This applies
    /// delta exactly once; already-encoded codec output would be scaled twice.
    /// No scratch allocation or extra NTT is introduced.
    ///
    /// # Correctness
    /// The caller supplies canonical residues and the intended plaintext lifts.
    ///
    /// # Panics
    /// Layout errors are rejected before sampling/writes. RNG or transform
    /// panics can leave partial output.
    pub fn encrypt_plaintext_crt_to<R, A, B>(
        &self,
        input: &CrtPolynomial<A>,
        output: &mut DcrtGlweCiphertext<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        assert_eq!(
            input.as_ref().len(),
            self.parameters.rns_poly_len(),
            "BFV CRT plaintext length mismatch"
        );
        self.raw.encrypt_with_body_to(output, rng, |body| {
            body.add_mul_factor_assign(
                input,
                self.parameters.delta_factor_mod_q().as_ref(),
                self.parameters.poly_length().get(),
                self.parameters.cipher_moduli_value(),
            );
        });
    }

    /// Overwrites a complete ciphertext with an encryption of zero, allocating nothing.
    /// Layout and panic conditions are those of the raw zero-encryption method.
    pub fn encrypt_zeros_to<R, B>(&self, output: &mut DcrtGlweCiphertext<B>, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = u64>,
    {
        self.raw.encrypt_zeros_to(output, rng);
    }

    /// Writes the DCRT phase `b-a*s`, without INTT, decoding or allocation.
    ///
    /// # Correctness
    /// Input must use this secret, ordered basis and NTT convention.
    ///
    /// # Panics
    /// Rejects incorrect input/output lengths before writes.
    pub fn phase_to<A, B>(&self, input: &DcrtGlweCiphertext<A>, output: &mut DcrtPolynomial<B>)
    where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        self.raw.phase_to(input, output);
    }

    /// Recovers N plaintext coefficients, allocating only the returned polynomial.
    /// All other storage is borrowed from the caller's reusable workspace.
    #[must_use]
    pub fn decrypt<A>(
        &self,
        input: &DcrtGlweCiphertext<A>,
        workspace: &mut BfvDecryptWorkspace,
    ) -> PolynomialOwned<u64>
    where
        A: Data<Elem = u64>,
    {
        let mut output = PolynomialOwned::zero(self.parameters.poly_length().get());
        self.decrypt_to(input, &mut output, workspace);
        output
    }

    /// Recovers plaintext coefficients into a complete output without allocation.
    /// Phase extraction overwrites scratch, followed by INTT and BFV decoding.
    ///
    /// # Correctness
    /// The ciphertext uses this key, Q basis and NTT representation; its complete
    /// phase error must satisfy the codec's recovery condition. Parameter checks
    /// cover fresh private encryption, not public/evaluated noise automatically.
    ///
    /// # Panics
    /// Complete input/output/workspace geometry is checked before writes.
    /// Transform/decoding panics may leave partial scratch or output.
    pub fn decrypt_to<A, B>(
        &self,
        input: &DcrtGlweCiphertext<A>,
        output: &mut Polynomial<B>,
        workspace: &mut BfvDecryptWorkspace,
    ) where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        assert_eq!(
            workspace.size(),
            self.parameters.size(),
            "BFV decryption workspace shape mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.parameters.poly_length().get(),
            "BFV plaintext output length mismatch"
        );
        let (phase, conversion) = workspace.as_mut();
        self.raw.phase_to(input, phase);
        self.table.inverse_transform_slice(phase.as_mut());
        self.parameters.codec().decode_coeffs_to(
            &mut CrtPolynomial(phase.as_mut()),
            output,
            conversion,
        );
    }
}
