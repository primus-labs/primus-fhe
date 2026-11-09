use crate::keys::BgvPublicKey;
use crate::parameters::compare_words;
use crate::workspace::BgvDecryptWorkspace;
use crate::{BgvCiphertext, BgvContext};
use primus_data::{Data, DataMut};
use primus_factor::{FactorSliceOps, ShoupFactor};
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, RnsDomainError};
use primus_integer::BigUint;
use primus_ntt::NttTable;
use primus_poly::{DcrtPolynomial, Polynomial, PolynomialOwned};
use primus_reduce::{Reduce, ReduceInv, ReduceMul, ReduceSub};
use primus_rns::Residues;

/// One full-ring secret and erasing recovery workspace borrowing a BGV context.
/// The complete N-coefficient secret is independent of plaintext slot capacity.
pub struct BgvClient<'a> {
    pub(crate) context: &'a BgvContext,
    key: DcrtGlweSecretKey<u64>,
    workspace: BgvDecryptWorkspace,
}

impl<'a> BgvClient<'a> {
    /// Borrows the exact shared context without exposing any secret material.
    #[must_use]
    pub fn context(&self) -> &'a BgvContext {
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

    /// Samples the complete coefficient secret and transforms it once into Q.
    /// Temporary coefficient secret storage is securely erased on drop.
    #[must_use]
    pub fn generate<R>(context: &'a BgvContext, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = context.parameters();
        let coefficient = GlweSecretKey::generate(
            parameters.size().glwe_size(),
            parameters.encryption_parameters().secret_key_sampler(),
            rng,
        );
        let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient, context.table());
        Self {
            context,
            key,
            workspace: BgvDecryptWorkspace::new(parameters),
        }
    }

    /// Takes ownership of an already transformed full-ring secret.
    ///
    /// # Correctness
    /// Key residues must be canonical in the ordered Q basis. NTT convention
    /// and actual coefficient distribution remain caller contracts.
    /// # Errors
    /// Rejects different complete geometry or ordered Q before allocating scratch.
    pub fn try_from_secret_key(
        context: &'a BgvContext,
        key: DcrtGlweSecretKey<u64>,
    ) -> Result<Self, RnsDomainError<u64>> {
        key.validate_parameters(
            context.parameters().size(),
            context.parameters().base_q().moduli(),
        )?;
        Ok(Self {
            context,
            key,
            workspace: BgvDecryptWorkspace::new(context.parameters()),
        })
    }

    /// Borrows the one full-ring secret for explicit advanced composition.
    #[must_use]
    pub(crate) fn secret_key(&self) -> &DcrtGlweSecretKey<u64> {
        &self.key
    }

    /// Generates a native public key whose phase is p times a fresh coefficient error.
    #[must_use]
    pub fn public_key<R: rand::Rng + rand::CryptoRng>(&self, rng: &mut R) -> BgvPublicKey {
        BgvPublicKey::generate(self, rng)
    }

    /// Encrypts coefficients, allocating only the returned level-zero ciphertext.
    /// See [`Self::encrypt_to`] for input, phase and failure contracts.
    #[must_use]
    pub fn encrypt<R, A>(&self, input: &Polynomial<A>, rng: &mut R) -> BgvCiphertext<Vec<u64>>
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
        &self,
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

    /// Encrypts N canonical coefficients using their unsigned integer lifts.
    /// Noise is p-scaled once; native c0 injection precedes its single NTT.
    ///
    /// # Panics
    /// Rejects recorded output context/level, incomplete lengths or noncanonical input
    /// before randomness or writes. RNG/transform failure may partially write output.
    pub fn encrypt_to<R, A, B>(
        &self,
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

    /// Encrypts canonical residues using centered integer lifts in the same ring.
    /// The allocation and panic contract is [`Self::encrypt_to`]'s.
    pub fn encrypt_centered_to<R, A, B>(
        &self,
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
        &self,
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
        self.encrypt_with_c0_to(output, rng, |c0| {
            add_plaintext(self.context, input.as_ref(), c0, centered)
        });
    }

    pub(crate) fn encrypt_zeros_to<R, B>(&self, output: &mut BgvCiphertext<B>, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = u64>,
    {
        self.encrypt_with_c0_to(output, rng, |_| {});
    }

    fn encrypt_with_c0_to<R, B>(
        &self,
        output: &mut BgvCiphertext<B>,
        rng: &mut R,
        inject: impl FnOnce(&mut [u64]),
    ) where
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = u64>,
    {
        output.check_binding(self.context, 0);
        let parameters = self.context.parameters();
        let n = parameters.poly_length().get();
        let sampling = parameters.encryption_parameters();
        let base = parameters.base_q();
        let length = parameters.size().rns_poly_len();
        let (mut c0, mut c1) = output.c0_c1_mut(length);
        sample_scaled_noise(self.context, 0, c0.as_mut(), rng);
        inject(c0.as_mut());
        for (table, limb) in self
            .context
            .table()
            .iter()
            .zip(c0.as_mut().chunks_exact_mut(n))
        {
            table.transform_slice(limb);
        }
        primus_distr::sample_crt_uniform_values_to(
            c1.as_mut(),
            n,
            sampling.cipher_moduli_uniform_distr(),
            rng,
        );
        let key = self.key.iter_dcrt_poly().next().expect("rank-one secret");
        c0.sub_mul_assign(&c1, &key, n, base.moduli());
        output.set_correction_factor(1);
    }

    /// Recovers coefficients using the ciphertext's recorded context and level.
    ///
    /// The intended centered phase must fit Q and use this client's actual secret.
    /// Context provenance does not establish a secret-key relationship.
    /// # Panics
    /// Rejects a foreign context, raw input or wrong plaintext length before writes.
    /// Raw interoperability uses [`Self::decrypt_at_level_to`].
    pub fn decrypt_to<A, B>(&mut self, input: &BgvCiphertext<A>, output: &mut Polynomial<B>)
    where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        let level = input.bound_level(self.context);
        self.recover_at_level_to(input, level, output);
    }

    /// Recovers N coefficients at a prepared level by exact centered CRT modulo p.
    /// Q may exceed 128 bits; no floating-point or BFV scaling/decoder is used.
    ///
    /// # Correctness
    /// Input has canonical per-limb residues and uses this actual secret, ordered
    /// Q and NTT convention. Its intended
    /// integer phase lift(f*m)+p*e must remain in the centered Q interval, where
    /// f is the ciphertext correction factor. Recovery first reduces that phase
    /// modulo p, then applies f^-1. Fresh private
    /// bounds do not automatically cover public or evaluated ciphertext noise.
    /// # Panics
    /// Rejects recorded context/level mismatches, unprepared levels or incorrect lengths
    /// before writes. NTT/RNS failures may partially overwrite output and erasing scratch.
    pub fn decrypt_at_level_to<A, B>(
        &mut self,
        input: &BgvCiphertext<A>,
        level: usize,
        output: &mut Polynomial<B>,
    ) where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        input.check_binding(self.context, level);
        self.recover_at_level_to(input, level, output);
    }

    // The entry point has already checked recorded context/level provenance.
    fn recover_at_level_to<A, B>(
        &mut self,
        input: &BgvCiphertext<A>,
        level: usize,
        output: &mut Polynomial<B>,
    ) where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        let parameters = self.context.parameters();
        let n = parameters.poly_length().get();
        let base = self.context.base_q(level);
        let count = base.moduli_count();
        let length = n * count;
        let (c0, c1) = input.c0_c1(length);
        assert_eq!(
            output.as_ref().len(),
            n,
            "BGV plaintext output length mismatch"
        );
        let mut phase = DcrtPolynomial(&mut self.workspace.phase.as_mut()[..length]);
        let secret = self.key.iter_dcrt_poly().next().expect("rank-one secret");
        phase.as_mut().copy_from_slice(c0.as_ref());
        phase.add_mul_assign(
            &c1,
            &DcrtPolynomial(&secret.as_ref()[..length]),
            n,
            base.moduli(),
        );
        for (table, limb) in self
            .context
            .table()
            .iter()
            .zip(phase.as_mut().chunks_exact_mut(n))
        {
            table.inverse_transform_slice(limb);
        }
        let p = parameters.plain_modulus();
        let width = base.big_uint_value_len();
        let half_q = self.context.half_q(level);
        let q_mod_p = self.context.q_mod_p(level);
        for (index, output) in output.as_mut().iter_mut().enumerate() {
            for (residue, limb) in self.workspace.residues[..count]
                .iter_mut()
                .zip(phase.as_ref().chunks_exact(n))
            {
                *residue = limb[index];
            }
            base.compose_to(
                Residues(&self.workspace.residues[..count]),
                BigUint(&mut self.workspace.value[..width]),
            );
            let value = &self.workspace.value[..width];
            let canonical = p.reduce(value);
            *output = if compare_words(value, half_q).is_gt() {
                p.reduce_sub(canonical, q_mod_p)
            } else {
                canonical
            };
        }
        // Existing factor-one recovery retains its exact loop. Only a general
        // chain's weighted message needs the final public scalar multiplication.
        let factor = input.correction_factor();
        if factor != 1 {
            ShoupFactor::new(p.reduce_inv(factor), p.value())
                .factor_mul_slice_assign(output.as_mut(), p.value());
        }
    }

    /// Recovers bound coefficients, allocating only the returned polynomial.
    /// See [`Self::decrypt_to`] for provenance and phase-bound contracts.
    #[must_use]
    pub fn decrypt<A: Data<Elem = u64>>(
        &mut self,
        input: &BgvCiphertext<A>,
    ) -> PolynomialOwned<u64> {
        let level = input.bound_level(self.context);
        let mut output = self.context.new_plaintext();
        self.recover_at_level_to(input, level, &mut output);
        output
    }

    /// Recovers coefficients, allocating only the returned full-ring polynomial.
    /// Raw input attests the supplied context, level, NTT order and actual secret.
    /// An already bound input must still match; see [`Self::decrypt_at_level_to`].
    #[must_use]
    pub fn decrypt_at_level<A: Data<Elem = u64>>(
        &mut self,
        input: &BgvCiphertext<A>,
        level: usize,
    ) -> PolynomialOwned<u64> {
        let mut output = self.context.new_plaintext();
        self.decrypt_at_level_to(input, level, &mut output);
        output
    }
}

pub(crate) fn validate_plaintext(context: &BgvContext, input: &[u64]) {
    assert_eq!(
        input.len(),
        context.parameters().poly_length().get(),
        "BGV plaintext length mismatch"
    );
    assert!(
        input
            .iter()
            .all(|&x| x < context.parameters().plain_modulus().value()),
        "BGV plaintext coefficient is not canonical"
    );
}

pub(crate) fn sample_scaled_noise<R: rand::Rng + rand::CryptoRng>(
    context: &BgvContext,
    level: usize,
    output: &mut [u64],
    rng: &mut R,
) {
    let parameters = context.parameters();
    let base = context.base_q(level);
    parameters
        .encryption_parameters()
        .sample_noise_to(output, base.moduli_values(), rng);
    for (limb, q) in output
        .chunks_exact_mut(parameters.poly_length().get())
        .zip(base.moduli())
    {
        for value in limb {
            *value = q.reduce_mul(*value, parameters.plain_modulus().value());
        }
    }
}

pub(crate) fn add_plaintext(
    context: &BgvContext,
    input: &[u64],
    output: &mut [u64],
    centered: bool,
) {
    use primus_reduce::ReduceAdd;
    let parameters = context.parameters();
    let p = parameters.plain_modulus().value();
    for (limb, q) in output
        .chunks_exact_mut(parameters.poly_length().get())
        .zip(parameters.base_q().moduli())
    {
        for (&message, value) in input.iter().zip(limb) {
            let lift = if centered && message >= p.div_ceil(2) {
                q.value() - (p - message)
            } else {
                message
            };
            *value = q.reduce_add(*value, lift);
        }
    }
}

#[cfg(all(test, feature = "batching"))]
mod tests {
    use crate::{BgvClient, BgvContext, BgvParameters, ErrorDistribution, SecretKeyDistr};
    use primus_modulus::BarrettModulus;
    use primus_shape::PolyLength;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn batching_does_not_embed_a_smaller_secret() {
        const M: usize = 32;
        for n in [64, 128] {
            let context = BgvContext::try_new(
                BgvParameters::try_coefficients(
                    PolyLength::new(n),
                    BarrettModulus::new(193),
                    &[BarrettModulus::new(1_125_899_906_248_961)],
                    SecretKeyDistr::SparseTernary,
                    ErrorDistribution::Gaussian {
                        standard_deviation: 0.849,
                    },
                )
                .unwrap(),
            )
            .unwrap();
            let mut rng = StdRng::seed_from_u64(0x09_5107 + n as u64);
            let client = BgvClient::generate(&context, &mut rng);
            assert_eq!(client.secret_key().rns_glwe_size().poly_length().get(), n);
            let key = client.secret_key().iter_dcrt_poly().next().unwrap();
            let mut coefficients = key.as_ref().to_vec();
            context.table().inverse_transform_slice(&mut coefficients);
            assert!(
                coefficients[..n]
                    .iter()
                    .enumerate()
                    .any(|(i, &x)| i % (n / M) != 0 && x != 0),
                "the secret must not be obtained by embedding a smaller-ring secret"
            );
        }
    }
}
