use primus_distr::DiscreteGaussian;
use primus_encoding::{MessageDecoder, RoundedCodec, ScaledCodec};
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lwe::LwePublicKey;
use primus_reduce::RingContext;
use primus_tfhe::{ClientError, EncryptionKey, LweClientParameters};

use crate::{
    CbsParameters, ExternalLweSecretKey, PbsOrder, PbsParameters, TfheClientError, TfheKeyError,
};

mod cbs;
mod external;

pub use cbs::CbsEncryptor;
pub use external::{BooleanDecryptor, BooleanEncryptor, Decryptor, Encryptor, ExternalLweClient};

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> PbsParameters<T, M, LM> {
    /// Binds the configured Rounded input shared by PBS, ManyLUT and factorized MVB.
    /// Copies the encoding state and borrows the active external secret and fresh
    /// noise sampler. No LUT or output codec is needed.
    ///
    /// # Correctness
    /// Signed GLWE coefficients inherit [`primus_lwe::LweSecretKeyRef`]'s range
    /// contract; binding checks layout and distribution, not coefficient magnitudes.
    pub fn encryptor<'a>(
        &'a self,
        key: ExternalLweSecretKey<'a, T>,
    ) -> Result<Encryptor<'a, T, M, primus_lwe::LweSecretKeyRef<'a, T>, LM>, TfheClientError> {
        self.encryptor_with_message_modulus(key, self.messages().input_modulus)
    }

    /// Binds a Rounded input message modulus without changing configured defaults.
    /// Reuses the external secret, ciphertext modulus and prepared noise sampler.
    /// Pair with the compiler's `messages.input_modulus`; this is not a q/Q override.
    /// The compiler checks programmable capacity separately from fresh encryption.
    ///
    /// # Correctness
    /// Inherits [`Self::encryptor`]'s secret contract. Changed message spacing
    /// needs a fresh-encryption and PBS-input noise budget.
    pub fn encryptor_with_message_modulus<'a>(
        &'a self,
        key: ExternalLweSecretKey<'a, T>,
        message_modulus: T,
    ) -> Result<Encryptor<'a, T, M, primus_lwe::LweSecretKeyRef<'a, T>, LM>, TfheClientError> {
        Ok(self.input_encryptor(key.bind(self)?, message_modulus)?)
    }

    /// Binds the configured Rounded input to an external LWE public key.
    /// Key identity and combined noise follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor<'a>(
        &'a self,
        key: &'a LwePublicKey<T>,
    ) -> Result<Encryptor<'a, T, M, &'a LwePublicKey<T>, LM>, ClientError> {
        self.public_encryptor_with_message_modulus(key, self.messages().input_modulus)
    }

    /// Binds a Rounded input override to the existing external public key.
    /// Shares [`Self::encryptor_with_message_modulus`]'s message/ciphertext domains
    /// and [`primus_tfhe::EncryptionKey`]'s public-key identity and noise contracts.
    pub fn public_encryptor_with_message_modulus<'a>(
        &'a self,
        key: &'a LwePublicKey<T>,
        message_modulus: T,
    ) -> Result<Encryptor<'a, T, M, &'a LwePublicKey<T>, LM>, ClientError> {
        self.input_encryptor(key, message_modulus)
    }

    /// Binds the configured Rounded output for ordinary PBS and ManyLUT.
    /// Copies decoding state and borrows only the external secret. Factorized
    /// MVB outputs require [`Self::mvb_decryptor`] instead.
    ///
    /// # Correctness
    /// Inherits [`Self::pbs_decryptor_with_message_modulus`]'s secret and recovery contracts.
    pub fn pbs_decryptor<'a>(
        &self,
        key: ExternalLweSecretKey<'a, T>,
    ) -> Result<Decryptor<'a, T, M, LM>, TfheClientError> {
        self.pbs_decryptor_with_message_modulus(key, self.messages().output_modulus)
    }

    /// Binds a Rounded output override for PBS/ManyLUT, independently of input t.
    /// The external secret and q/Q still follow the configured PBS order.
    /// Pair with the compiler's `messages.output_modulus`; existing clients and
    /// defaults remain unchanged. Scaled outputs use [`Self::ring_return_decryptor`].
    ///
    /// # Correctness
    /// The producing operation must use this message modulus and Rounded encoding.
    /// Include prior error, KS and Q→q rounding in its decoding budget.
    /// Inherits [`Self::encryptor`]'s signed-secret range contract.
    pub fn pbs_decryptor_with_message_modulus<'a>(
        &self,
        key: ExternalLweSecretKey<'a, T>,
        message_modulus: T,
    ) -> Result<Decryptor<'a, T, M, LM>, TfheClientError> {
        self.output_decryptor(key, message_modulus, OutputEncoding::Rounded)
    }

    /// Binds the configured Scaled output for factorized MVB.
    /// Copies decoding state and borrows only the external secret. Codec validity
    /// does not establish the factor amplification, transform or return noise budget.
    ///
    /// # Correctness
    /// Inherits [`Self::ring_return_decryptor`]'s secret and recovery contracts.
    pub fn mvb_decryptor<'a>(
        &self,
        key: ExternalLweSecretKey<'a, T>,
    ) -> Result<Decryptor<'a, T, M, LM>, TfheClientError> {
        self.ring_return_decryptor(key, self.messages().output_modulus)
    }

    /// Decodes a returned Scaled ring phase with explicit message modulus `t_ring`.
    /// Uses the external secret and modulus selected by the PBS order. This does
    /// not change the configured PBS/MVB message moduli or the ring's encoding.
    ///
    /// # Correctness
    /// `t_ring` must match the original ring encoding. Budget the difference
    /// between the rescaled Q-encoding center and the q-encoding center as well
    /// as ring-operation, KS and Q→q rounding error. Inherits
    /// [`Self::encryptor`]'s signed-secret range contract.
    pub fn ring_return_decryptor<'a>(
        &self,
        key: ExternalLweSecretKey<'a, T>,
        t_ring: T,
    ) -> Result<Decryptor<'a, T, M, LM>, TfheClientError> {
        self.output_decryptor(key, t_ring, OutputEncoding::Scaled)
    }

    /// Generates an LWE public key using only the selected external secret.
    /// Uses small-LWE noise for BR→KS, or accumulator fresh noise for KS→BR.
    /// The signed kN secret is borrowed without a coefficient copy.
    ///
    /// # Correctness
    /// The secret inherits [`primus_lwe::LweSecretKeyRef`]'s range contract.
    /// Public-key usage and security follow [`crate::LwePublicKey`] and
    /// [`crate::EncryptionKey`]; shape/domain checks do not prove secret identity.
    ///
    /// # Errors
    /// Rejects an incompatible external role, layout, distribution or LWE modulus,
    /// and small-LWE coefficients outside the binary/ternary domain.
    ///
    /// # Panics
    /// Panics if public-key storage `d * (d + 1)` overflows for external dimension d.
    pub fn try_generate_public_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        key: ExternalLweSecretKey<'_, T>,
        rng: &mut R,
    ) -> Result<LwePublicKey<T>, TfheKeyError> {
        let key = key.bind(self)?;
        Ok(match self.external_domain() {
            ExternalLweClient::Small(domain) => domain.generate_public_key(key, rng),
            ExternalLweClient::Ring(domain) => domain.generate_public_key(key, rng),
        })
    }

    // Select the concrete reducer once before constructing either a secret-key
    // or public-key client. The owning secret has already been bound by the caller.
    fn input_encryptor<Key>(
        &self,
        key: Key,
        message_modulus: T,
    ) -> Result<Encryptor<'_, T, M, Key, LM>, ClientError>
    where
        Key: EncryptionKey<T, M> + EncryptionKey<T, LM>,
    {
        Ok(match self.external_domain() {
            ExternalLweClient::Small(domain) => {
                ExternalLweClient::Small(domain.encryptor(message_modulus, key)?)
            }
            ExternalLweClient::Ring(domain) => {
                ExternalLweClient::Ring(domain.encryptor(message_modulus, key)?)
            }
        })
    }

    // Output encoding changes recovery checks, not the external secret or modulus.
    // Decoders copy their prepared state and retain no borrow of this domain.
    fn output_decryptor<'a>(
        &self,
        key: ExternalLweSecretKey<'a, T>,
        message_modulus: T,
        encoding: OutputEncoding,
    ) -> Result<Decryptor<'a, T, M, LM>, TfheClientError> {
        let key = key.bind(self)?;
        Ok(match self.external_domain() {
            ExternalLweClient::Small(domain) => {
                ExternalLweClient::Small(domain.decryptor(message_modulus, key, encoding)?)
            }
            ExternalLweClient::Ring(domain) => {
                ExternalLweClient::Ring(domain.decryptor(message_modulus, key, encoding)?)
            }
        })
    }

    /// Select all external sampling state together. This borrowed view neither
    /// rebuilds samplers nor enters coefficient kernels; BR controls always keep
    /// their independent small-q parameters, including in KS→BR mode.
    fn external_domain(
        &self,
    ) -> ExternalLweClient<ClientDomain<'_, T, LM>, ClientDomain<'_, T, M>> {
        match self.pbs_order() {
            PbsOrder::BootstrapKeyswitch => {
                let lwe = self.small_lwe();
                ExternalLweClient::Small(ClientDomain {
                    dimension: lwe.dimension(),
                    modulus: lwe.cipher_modulus(),
                    noise: lwe.noise_distribution(),
                })
            }
            PbsOrder::KeyswitchBootstrap => {
                let glwe = self.blind_rotation_params();
                ExternalLweClient::Ring(ClientDomain {
                    dimension: LweDimension::from(glwe.glwe_size()),
                    modulus: glwe.cipher_modulus(),
                    noise: glwe.noise_distribution(),
                })
            }
        }
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> CbsParameters<T, M, LM> {
    /// Binds the CBS input geometry and active external secret. Ordinary PBS's
    /// input encoding remains independent. Inherits the signed-secret contract
    /// of [`PbsParameters::encryptor`].
    pub fn encryptor<'a>(
        &'a self,
        key: ExternalLweSecretKey<'a, T>,
    ) -> Result<CbsEncryptor<'a, T, M, primus_lwe::LweSecretKeyRef<'a, T>, LM>, TfheClientError>
    {
        let pbs = self.pbs_parameters();
        Ok(CbsEncryptor::new(
            pbs.input_encryptor(key.bind(pbs)?, self.br_control_codec().plaintext_modulus())?,
            self.input_encoding(),
        ))
    }

    /// Binds a public key to the same CBS input geometry as the private client.
    /// Key identity and combined noise follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor<'a>(
        &'a self,
        key: &'a LwePublicKey<T>,
    ) -> Result<CbsEncryptor<'a, T, M, &'a LwePublicKey<T>, LM>, ClientError> {
        Ok(CbsEncryptor::new(
            self.pbs_parameters()
                .input_encryptor(key, self.br_control_codec().plaintext_modulus())?,
            self.input_encoding(),
        ))
    }
}

/// The producing operation determines which codec's recovery condition to check.
/// Selection is used only during client construction, not during decryption.
enum OutputEncoding {
    Rounded,
    Scaled,
}

/// One borrowed sampling domain, selected before constructing any client. Unlike
/// a runtime modulus wrapper, M remains concrete in all coefficient operations.
struct ClientDomain<'a, T: FheUint, M: RingContext<T>> {
    dimension: LweDimension,
    modulus: M,
    noise: &'a DiscreteGaussian<T>,
}

impl<'a, T: FheUint, M: RingContext<T>> ClientDomain<'a, T, M> {
    fn encryptor<Key: EncryptionKey<T, M>>(
        self,
        message_modulus: T,
        key: Key,
    ) -> Result<primus_tfhe::Encryptor<'a, T, M, Key>, ClientError> {
        let codec = RoundedCodec::try_new(message_modulus, self.modulus)?;
        let parameters = LweClientParameters::try_from_parts(self.dimension, &codec, self.noise)?;
        primus_tfhe::Encryptor::try_new(parameters, key)
    }

    fn decryptor<'key>(
        self,
        message_modulus: T,
        key: primus_lwe::LweSecretKeyRef<'key, T>,
        encoding: OutputEncoding,
    ) -> Result<primus_tfhe::Decryptor<'key, T, M>, ClientError> {
        let decoder = match encoding {
            OutputEncoding::Rounded => {
                MessageDecoder::from(&RoundedCodec::try_new(message_modulus, self.modulus)?)
            }
            OutputEncoding::Scaled => {
                MessageDecoder::from(&ScaledCodec::try_new(message_modulus, self.modulus)?)
            }
        };
        Ok(primus_tfhe::Decryptor::new(decoder, key))
    }

    fn generate_public_key<R: rand::Rng + rand::CryptoRng>(
        self,
        key: primus_lwe::LweSecretKeyRef<'_, T>,
        rng: &mut R,
    ) -> LwePublicKey<T> {
        LwePublicKey::generate(
            key,
            self.dimension,
            self.modulus,
            self.modulus.uniform_distribution(),
            self.noise,
            rng,
        )
    }
}
