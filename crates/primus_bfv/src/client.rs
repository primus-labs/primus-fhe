use primus_data::{Data, DataMut};
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, RnsDomainError};
use primus_ntt::NttTable;
use primus_poly::{CrtPolynomial, DcrtPolynomial, Polynomial, PolynomialOwned};

use crate::keys::BfvPublicKey;
use crate::secret_key::{BfvSecretKeyContext, phase_with_secret_to};
use crate::workspace::BfvDecryptWorkspace;
use crate::{BfvCiphertext, BfvContext};

/// A single secret and erasing recovery workspace borrowing shared BFV resources.
///
/// The secret is stored only once at the highest Q. Lower-level recovery borrows
/// its DCRT prefix, without secret cloning, new transforms or new samplers.
/// Fresh secret/public encryption is at level zero; evaluation and switching do
/// not require this client. Mutable access serializes recovery workspace reuse.
pub struct BfvClient<'a> {
    pub(crate) context: &'a BfvContext,
    key: DcrtGlweSecretKey<u64>,
    workspace: BfvDecryptWorkspace,
}

impl<'a> BfvClient<'a> {
    /// Shared numerical resources borrowed by this individual owner.
    #[must_use]
    pub fn context(&self) -> &'a BfvContext {
        self.context
    }

    /// Consumes this client and transfers its single transformed secret owner.
    ///
    /// This is the owned counterpart of [`Self::try_from_secret_key`], useful
    /// when one party changes scheme roles without cloning its private share.
    /// Recovery scratch is dropped and erased. The receiving role must check
    /// complete geometry and use the key's actual NTT roots and order; moving
    /// storage does not establish cross-scheme transform compatibility.
    #[must_use]
    pub fn into_secret_key(self) -> DcrtGlweSecretKey<u64> {
        self.key
    }

    /// Samples one coefficient secret and transforms it once into the full basis.
    /// The temporary coefficient secret is securely erased when it is dropped.
    #[must_use]
    pub fn generate<R: rand::Rng + rand::CryptoRng>(context: &'a BfvContext, rng: &mut R) -> Self {
        let parameters = context.parameters();
        let coefficient_key = GlweSecretKey::generate(
            parameters.size().glwe_size(),
            parameters.encryption_parameters().secret_key_sampler(),
            rng,
        );
        let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, context.table());
        Self {
            context,
            key,
            workspace: BfvDecryptWorkspace::new(parameters),
        }
    }

    /// Takes ownership of one already transformed highest-level secret.
    ///
    /// # Correctness
    /// The key must use this context's actual NTT convention. Distribution
    /// metadata does not prove the imported key's coefficient magnitude.
    ///
    /// # Errors
    /// Rejects different complete geometry or ordered Q before allocating scratch.
    pub fn try_from_secret_key(
        context: &'a BfvContext,
        key: DcrtGlweSecretKey<u64>,
    ) -> Result<Self, RnsDomainError<u64>> {
        key.validate_parameters(
            context.parameters().size(),
            context.parameters().base_q().moduli(),
        )?;
        Ok(Self {
            context,
            key,
            workspace: BfvDecryptWorkspace::new(context.parameters()),
        })
    }

    /// Borrows the single highest-level secret for native evaluation-key generation.
    #[must_use]
    pub(crate) fn secret_key(&self) -> &DcrtGlweSecretKey<u64> {
        &self.key
    }

    fn secret_context(&self) -> BfvSecretKeyContext<'_> {
        // Generation/import established the key pairing; the context owns the
        // one checked table. Rebuilding this borrow performs no repeated checks.
        BfvSecretKeyContext::from_validated(&self.key, self.context)
    }

    /// Creates a native public key at level zero without cloning the secret.
    #[must_use]
    pub fn public_key<R: rand::Rng + rand::CryptoRng>(&self, rng: &mut R) -> BfvPublicKey {
        BfvPublicKey::new(&self.secret_context(), rng)
    }

    /// Allocates a level-zero ciphertext and encrypts canonical coefficients.
    ///
    /// Inherits [`Self::encrypt_to`]'s representation and input checks. Only the
    /// output is allocated; use `_to` to reuse caller-owned output storage.
    ///
    /// # Panics
    /// Rejects invalid plaintext before RNG consumption; allocation can precede
    /// the validation. See [`Self::encrypt_to`] for partial-write conditions.
    #[must_use]
    pub fn encrypt<R, A>(&self, input: &Polynomial<A>, rng: &mut R) -> BfvCiphertext<Vec<u64>>
    where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = u64>,
    {
        let mut output = self.context.new_ciphertext(0);
        self.encrypt_to(input, &mut output, rng);
        output
    }

    /// Allocates and encrypts using centered lift; see [`Self::encrypt`].
    #[must_use]
    pub fn encrypt_centered<R, A>(
        &self,
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

    /// Encrypts N canonical plaintext coefficients at level zero with unsigned lift.
    ///
    /// Applies delta exactly once and allocates nothing.
    ///
    /// # Panics
    /// Rejects recorded output context/level conflicts, noncanonical plaintext
    /// or incorrect complete lengths before RNG
    /// consumption or output writes. RNG/NTT panics may leave partial output.
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
        self.secret_context().encrypt_to(input, output, rng);
    }

    /// Encrypts at level zero with centered lift; see [`Self::encrypt_to`].
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
        self.secret_context()
            .encrypt_centered_to(input, output, rng);
    }

    /// Recovers normal bound ciphertext storage at its recorded level.
    ///
    /// # Panics
    /// Rejects raw or foreign-context input before recovery writes. The actual
    /// secret and complete evaluated recovery bound remain caller contracts.
    pub fn decrypt_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BfvCiphertext<A>,
        output: &mut Polynomial<B>,
    ) {
        let level = input.bound_level(self.context);
        self.recover_at_level_to(input, level, output);
    }

    /// Allocates and recovers a normal bound ciphertext at its recorded level.
    /// Inherits [`Self::decrypt_to`]'s representation and recovery contract.
    #[must_use]
    pub fn decrypt<A: Data<Elem = u64>>(
        &mut self,
        input: &BfvCiphertext<A>,
    ) -> PolynomialOwned<u64> {
        let level = input.bound_level(self.context);
        let mut output = self.context.new_plaintext();
        self.recover_at_level_to(input, level, &mut output);
        output
    }

    /// Recovers N plaintext coefficients at an explicit level without allocation.
    ///
    /// # Correctness
    /// Input uses this secret and context's NTT representation at `level`.
    /// Explicit raw storage is caller-attested; bound input must match its
    /// immutable local context and level, including through borrowed views.
    /// Recovery uses the level's unique fast codec. It returns the exact message
    /// under that codec's complete phase-error bound (including encoding drift
    /// and auxiliary-modulus margin); it is not arbitrary-phase exact rounding.
    /// Fresh bounds do not automatically cover public or evaluated ciphertexts.
    ///
    /// # Panics
    /// Rejects recorded context/level conflicts, an unprepared level or incorrect
    /// complete lengths before writes.
    /// Transform/codec panics can leave partial scratch or output.
    pub fn decrypt_at_level_to<A, B>(
        &mut self,
        input: &BfvCiphertext<A>,
        level: usize,
        output: &mut Polynomial<B>,
    ) where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        input.check_binding(self.context, level);
        self.recover_at_level_to(input, level, output);
    }

    // Both entry points have established the ciphertext's level/provenance contract.
    fn recover_at_level_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BfvCiphertext<A>,
        level: usize,
        output: &mut Polynomial<B>,
    ) {
        let codec = self.context.codec(level);
        let n = self.context.parameters().poly_length().get();
        let length = n * codec.moduli_count();
        assert_eq!(
            output.as_ref().len(),
            n,
            "BFV plaintext output length mismatch"
        );
        let (phase, conversion) = self.workspace.as_mut();
        let mut phase = DcrtPolynomial(&mut phase.as_mut()[..length]);
        let key = self.key.iter_dcrt_poly().next().expect("rank-one secret");
        phase_with_secret_to(
            input,
            &key.as_ref()[..length],
            &mut phase,
            n,
            codec.base_q().moduli(),
        );
        for (table, limb) in self
            .context
            .table()
            .iter()
            .zip(phase.as_mut().chunks_exact_mut(n))
        {
            table.inverse_transform_slice(limb);
        }
        codec.decode_coeffs_to(
            &mut CrtPolynomial(phase.as_mut()),
            output,
            &mut conversion[..codec.decode_scratch_len(n)],
        );
    }

    /// Recovers at an explicit level, allocating only the returned polynomial.
    /// The representation, noise and panic contracts are [`Self::decrypt_at_level_to`]'s.
    #[must_use]
    pub fn decrypt_at_level<A: Data<Elem = u64>>(
        &mut self,
        input: &BfvCiphertext<A>,
        level: usize,
    ) -> PolynomialOwned<u64> {
        let mut output = self.context.new_plaintext();
        self.decrypt_at_level_to(input, level, &mut output);
        output
    }
}
