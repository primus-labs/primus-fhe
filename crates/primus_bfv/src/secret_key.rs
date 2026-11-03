use primus_data::{Data, DataMut};
use primus_encoding::PlaintextEmbedding;
use primus_glwe_rns::{DcrtGlweSecretKey, RnsDomainError};
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_poly::{CrtPolynomial, DcrtPolynomial, Polynomial, PolynomialOwned};

use crate::{BfvCiphertext, BfvDecryptWorkspace, BfvParameters};

/// A secret key bound to rank-one BFV parameters and their ordered NTT table.
///
/// Binding checks geometry and numerical basis/table order without allocating
/// or cloning the key. Matching numbers do not establish actual secret identity,
/// NTT root/evaluation identity or evaluated ciphertext noise margin.
pub struct BfvSecretKeyContext<'a> {
    key: &'a DcrtGlweSecretKey<u64>,
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
        parameters.validate_table(table)?;
        key.validate_parameters(parameters.size(), parameters.base_q().moduli())?;
        Ok(Self {
            key,
            parameters,
            table,
        })
    }

    pub(crate) fn from_validated(
        key: &'a DcrtGlweSecretKey<u64>,
        parameters: &'a BfvParameters,
        table: &'a U64DcrtTable,
    ) -> Self {
        Self {
            key,
            parameters,
            table,
        }
    }

    pub(crate) fn parameters(&self) -> &'a BfvParameters {
        self.parameters
    }

    /// Encrypts N coefficients in `[0,t)` using unsigned BFV embedding.
    ///
    /// Applies delta exactly once, adding the encoding to coefficient noise
    /// before c0's sole forward NTT. No scratch allocation occurs.
    ///
    /// # Panics
    /// Complete input/output lengths and canonical coefficients are checked
    /// before sampling or writes. Codec, RNG or transform panics can leave
    /// partial output.
    pub fn encrypt_to<R, A, B>(
        &self,
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

    /// Encrypts N coefficients in `[0,t)` using centered BFV embedding.
    /// The layout, allocation and panic contract is [`Self::encrypt_to`]'s.
    pub fn encrypt_centered_to<R, A, B>(
        &self,
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
        &self,
        input: &Polynomial<A>,
        output: &mut BfvCiphertext<B>,
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
        assert!(
            input
                .as_ref()
                .iter()
                .all(|&x| x < self.parameters.codec().t()),
            "BFV plaintext coefficient is not canonical"
        );
        self.encrypt_with_c0_to(output, rng, |c0| {
            self.parameters
                .codec()
                .add_encode_coeffs_assign(input, c0, embedding);
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
    pub fn encrypt_plaintext_lift_crt_to<R, A, B>(
        &self,
        input: &CrtPolynomial<A>,
        output: &mut BfvCiphertext<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        assert_eq!(
            input.as_ref().len(),
            self.parameters.size().rns_poly_len(),
            "BFV CRT plaintext length mismatch"
        );
        self.encrypt_with_c0_to(output, rng, |c0| {
            c0.add_mul_factor_assign(
                input,
                self.parameters.codec().delta_factor_mod_q().as_ref(),
                self.parameters.poly_length().get(),
                self.parameters.codec().moduli_values(),
            );
        });
    }

    /// Overwrites a complete ciphertext with an encryption of zero, allocating nothing.
    /// # Panics
    /// Checks the complete output before sampling. RNG/NTT panics may leave
    /// partially written output.
    pub fn encrypt_zeros_to<R, B>(&self, output: &mut BfvCiphertext<B>, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = u64>,
    {
        self.encrypt_with_c0_to(output, rng, |_| {});
    }

    /// Writes the DCRT phase `c0+c1*s`, without INTT, decoding or allocation.
    ///
    /// # Correctness
    /// Input must use this secret, ordered basis and NTT convention.
    ///
    /// # Panics
    /// Rejects incorrect input/output lengths before writes.
    pub fn phase_to<A, B>(&self, input: &BfvCiphertext<A>, output: &mut DcrtPolynomial<B>)
    where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        assert_eq!(
            output.as_ref().len(),
            self.parameters.size().rns_poly_len(),
            "BFV phase output length mismatch"
        );
        phase_with_secret_to(
            input,
            self.key
                .iter_dcrt_poly()
                .next()
                .expect("rank-one secret")
                .as_ref(),
            output,
            self.parameters.poly_length().get(),
            self.parameters.base_q().moduli(),
        );
    }

    /// Recovers N plaintext coefficients, allocating only the returned polynomial.
    /// All other storage is borrowed from the caller's reusable workspace.
    #[must_use]
    pub fn decrypt<A>(
        &self,
        input: &BfvCiphertext<A>,
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
        input: &BfvCiphertext<A>,
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
        self.phase_to(input, phase);
        self.table.inverse_transform_slice(phase.as_mut());
        self.parameters.codec().decode_coeffs_to(
            &mut CrtPolynomial(phase.as_mut()),
            output,
            conversion,
        );
    }

    /// Encrypts an already-scaled coefficient-domain CRT phase directly.
    ///
    /// Unlike [`Self::encrypt_plaintext_lift_crt_to`], no delta is applied.
    /// This entry is for callers that deliberately prepared their own encoding.
    /// It allocates no storage and fuses injection before c0's single NTT.
    ///
    /// # Correctness
    /// Canonical residues use the parameter Q order and intended encoding.
    /// Recovery still requires the complete phase error to meet the codec bound.
    ///
    /// # Panics
    /// Incorrect complete input/output lengths are rejected before sampling.
    /// RNG or transform panics may leave partial output.
    pub fn encrypt_encoded_crt_to<R, A, B>(
        &self,
        input: &CrtPolynomial<A>,
        output: &mut BfvCiphertext<B>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        assert_eq!(
            input.as_ref().len(),
            self.parameters.size().rns_poly_len(),
            "BFV encoded phase length mismatch"
        );
        self.encrypt_with_c0_to(output, rng, |c0| {
            c0.add_assign(
                input,
                self.parameters.poly_length().get(),
                self.parameters.base_q().moduli(),
            )
        });
    }

    fn encrypt_with_c0_to<R, B>(
        &self,
        output: &mut BfvCiphertext<B>,
        rng: &mut R,
        inject: impl FnOnce(&mut CrtPolynomial<&mut [u64]>),
    ) where
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = u64>,
    {
        let parameters = self.parameters;
        let n = parameters.poly_length().get();
        let sampling = parameters.encryption_parameters();
        let (mut c0, mut c1) = output.c0_c1_mut(parameters.size().rns_poly_len());
        sampling.sample_noise_to(c0.as_mut(), parameters.codec().moduli_values(), rng);
        inject(&mut CrtPolynomial(c0.as_mut()));
        self.table.transform_slice(c0.as_mut());
        primus_distr::sample_crt_uniform_values_to(
            c1.as_mut(),
            n,
            sampling.cipher_moduli_uniform_distr(),
            rng,
        );
        // Native BFV: c0 = encoded + e - c1*s, without converting raw GLWE.
        c0.sub_mul_assign(
            &c1,
            &self.key.iter_dcrt_poly().next().expect("rank-one secret"),
            n,
            parameters.base_q().moduli(),
        );
    }
}

// Both public entry points establish full geometry. Lower-level recovery borrows
// the already validated highest-level secret prefix rather than copying a key.
pub(crate) fn phase_with_secret_to<A, B>(
    input: &BfvCiphertext<A>,
    secret: &[u64],
    output: &mut DcrtPolynomial<B>,
    n: usize,
    moduli: &[BarrettModulus<u64>],
) where
    A: Data<Elem = u64>,
    B: DataMut<Elem = u64>,
{
    let (c0, c1) = input.c0_c1(secret.len());
    output.as_mut().copy_from_slice(c0.as_ref());
    output.add_mul_assign(&c1, &DcrtPolynomial(secret), n, moduli);
}
