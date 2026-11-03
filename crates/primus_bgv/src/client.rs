use crate::parameters::compare_words;
use crate::workspace::BgvDecryptWorkspace;
use crate::{BgvCiphertext, BgvContext, BgvPublicKey};
use primus_data::{Data, DataMut};
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, RnsDomainError};
use primus_integer::BigUint;
use primus_poly::{DcrtPolynomial, Polynomial, PolynomialOwned};
use primus_reduce::{Reduce, ReduceMul, ReduceSub};
use primus_rns::Residues;

/// One full-ring secret and erasing recovery workspace borrowing a BGV context.
/// The complete N-coefficient secret is independent of plaintext slot capacity.
pub struct BgvClient<'a> {
    context: &'a BgvContext,
    key: DcrtGlweSecretKey<u64>,
    workspace: BgvDecryptWorkspace,
}

impl<'a> BgvClient<'a> {
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
    pub fn secret_key(&self) -> &DcrtGlweSecretKey<u64> {
        &self.key
    }

    /// Generates a native public key whose phase is p times a fresh coefficient error.
    #[must_use]
    pub fn public_key<R: rand::Rng + rand::CryptoRng>(&self, rng: &mut R) -> BgvPublicKey {
        BgvPublicKey::generate(self, self.context, rng)
    }

    /// Encrypts N canonical coefficients using their unsigned integer lifts.
    /// Noise is p-scaled once; native c0 injection precedes its single NTT.
    ///
    /// # Panics
    /// Rejects incomplete output, wrong input length or noncanonical coefficients
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
        let parameters = self.context.parameters();
        let n = parameters.poly_length().get();
        let sampling = parameters.encryption_parameters();
        let (mut c0, mut c1) = output.c0_c1_mut(self.context.rns_poly_len());
        sample_scaled_noise(self.context, c0.as_mut(), rng);
        inject(c0.as_mut());
        self.context.table().transform_slice(c0.as_mut());
        primus_distr::sample_crt_uniform_values_to(
            c1.as_mut(),
            n,
            sampling.cipher_moduli_uniform_distr(),
            rng,
        );
        c0.sub_mul_assign(
            &c1,
            &self.key.iter_dcrt_poly().next().expect("rank-one secret"),
            n,
            parameters.base_q().moduli(),
        );
    }

    /// Writes the native DCRT phase c0+c1*s without transform or decoding.
    ///
    /// # Correctness
    /// Input has canonical per-limb residues and uses this actual secret and
    /// context's ordered Q and NTT convention.
    /// # Panics
    /// Rejects incorrect complete lengths before output writes.
    pub fn phase_to<A, B>(&self, input: &BgvCiphertext<A>, output: &mut DcrtPolynomial<B>)
    where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        assert_eq!(
            output.as_ref().len(),
            self.context.rns_poly_len(),
            "BGV phase output length mismatch"
        );
        phase_to(self.context, &self.key, input, output);
    }

    /// Recovers N coefficients by exact centered CRT reconstruction modulo p.
    /// Q may exceed 128 bits; no floating-point or BFV scaling/decoder is used.
    ///
    /// # Correctness
    /// Input has canonical per-limb residues and uses this actual secret, ordered
    /// Q and NTT convention. Its intended
    /// integer phase m+p*e must remain in the centered Q interval. Fresh private
    /// bounds do not automatically cover public or evaluated ciphertext noise.
    /// # Panics
    /// Rejects incorrect complete input/output lengths before writes. NTT/RNS
    /// failures may partially overwrite output and erasing scratch.
    pub fn decrypt_to<A, B>(&mut self, input: &BgvCiphertext<A>, output: &mut Polynomial<B>)
    where
        A: Data<Elem = u64>,
        B: DataMut<Elem = u64>,
    {
        let parameters = self.context.parameters();
        let n = parameters.poly_length().get();
        assert_eq!(
            input.as_ref().len(),
            parameters.size().rns_glwe_len(),
            "BGV ciphertext length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            n,
            "BGV plaintext output length mismatch"
        );
        phase_to(self.context, &self.key, input, &mut self.workspace.phase);
        self.context
            .table()
            .inverse_transform_slice(self.workspace.phase.as_mut());
        let p = parameters.plain_modulus();
        for (index, output) in output.as_mut().iter_mut().enumerate() {
            for (residue, limb) in self
                .workspace
                .residues
                .iter_mut()
                .zip(self.workspace.phase.as_ref().chunks_exact(n))
            {
                *residue = limb[index];
            }
            parameters.base_q().compose_to(
                Residues(&self.workspace.residues),
                BigUint(&mut self.workspace.value[..]),
            );
            let canonical = p.reduce(self.workspace.value.as_slice());
            *output = if compare_words(&self.workspace.value, &parameters.half_q).is_gt() {
                p.reduce_sub(canonical, parameters.q_mod_p)
            } else {
                canonical
            };
        }
    }

    /// Recovers coefficients, allocating only the returned full-ring polynomial.
    /// See [`Self::decrypt_to`] for the representation and phase-bound contracts.
    #[must_use]
    pub fn decrypt<A: Data<Elem = u64>>(
        &mut self,
        input: &BgvCiphertext<A>,
    ) -> PolynomialOwned<u64> {
        let mut output = PolynomialOwned::zero(self.context.parameters().poly_length().get());
        self.decrypt_to(input, &mut output);
        output
    }
}

fn phase_to<A, B>(
    context: &BgvContext,
    key: &DcrtGlweSecretKey<u64>,
    input: &BgvCiphertext<A>,
    output: &mut DcrtPolynomial<B>,
) where
    A: Data<Elem = u64>,
    B: DataMut<Elem = u64>,
{
    let (c0, c1) = input.c0_c1(context.rns_poly_len());
    output.as_mut().copy_from_slice(c0.as_ref());
    output.add_mul_assign(
        &c1,
        &key.iter_dcrt_poly().next().expect("rank-one secret"),
        context.parameters().poly_length().get(),
        context.parameters().base_q().moduli(),
    );
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
    output: &mut [u64],
    rng: &mut R,
) {
    let parameters = context.parameters();
    parameters.encryption_parameters().sample_noise_to(
        output,
        parameters.base_q().moduli_values(),
        rng,
    );
    for (limb, q) in output
        .chunks_exact_mut(parameters.poly_length().get())
        .zip(parameters.base_q().moduli())
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
