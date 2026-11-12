//! Server evaluation material and paired or component key generation.

mod circuit;
pub use circuit::CircuitBootstrapServerKey;

mod blind_rotation;
mod classic;
pub use blind_rotation::BlindRotationKey;
pub(crate) use blind_rotation::BootstrappingControls;
use blind_rotation::Controls;
use num_traits::{ConstOne, ConstZero};
use primus_integer::FheUint;
use primus_lattice::nlev::NttNlev;
use primus_ntru::{
    NtruError, NtruLweKeySwitchingKey, NtruSecretKey, NttNtruGadgetEncryptWorkspace,
    NttNtruSecretKey,
};
use primus_ntt::MonomialNttTable;
use primus_tfhe_ntru::BlockNtruKeyLayout;
use zeroize::Zeroizing;

use crate::{BlindRotationMethod, ClientKey, KeyGenerationError, TfheContext};
pub use classic::ClassicControls;

/// Public setup geometry checked before sampling or key allocation.
enum BlindRotationLayout<T: FheUint> {
    Classic,
    Block(BlockNtruKeyLayout<T>),
}

/// Owning PBS bundle: blind rotation and required LWE return material.
/// Components can be generated independently and moved in or out without copying
/// ciphertext buffers. Evaluator binding validates the required components only.
pub struct ServerKey<T: FheUint> {
    blind_rotation: BlindRotationKey<T>,
    key_switching_key: NtruLweKeySwitchingKey<T>,
}

impl<T: FheUint> ServerKey<T> {
    /// Moves BR and KS material into one bundle without copying buffers.
    /// Evaluator binding checks layouts; actual secret and transform identity
    /// remain caller requirements.
    #[must_use]
    pub fn new(
        blind_rotation: BlindRotationKey<T>,
        key_switching_key: NtruLweKeySwitchingKey<T>,
    ) -> Self {
        Self {
            blind_rotation,
            key_switching_key,
        }
    }

    /// Borrows the selected Classic or Block blind-rotation material.
    #[must_use]
    #[inline]
    pub fn blind_rotation_key(&self) -> &BlindRotationKey<T> {
        &self.blind_rotation
    }

    /// Borrows the required Q→q, f→s return key.
    #[must_use]
    #[inline]
    pub fn key_switching_key(&self) -> &NtruLweKeySwitchingKey<T> {
        &self.key_switching_key
    }

    /// Moves out BR and KS material without copying ciphertext buffers.
    #[must_use]
    pub fn into_parts(self) -> (BlindRotationKey<T>, NtruLweKeySwitchingKey<T>) {
        (self.blind_rotation, self.key_switching_key)
    }
}

/// Generates coefficient and exact-NTT keys for one NTRU TFHE context.
pub struct KeyGenerator<'a, T, Table, LM = primus_modulus::BarrettModulus<T>>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    pub(crate) context: &'a TfheContext<T, Table, LM>,
    pub(crate) gadget: NttNtruGadgetEncryptWorkspace<T>,
}

impl<'a, T, Table, LM> KeyGenerator<'a, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Creates a key generator with reusable gadget-encryption workspace.
    #[must_use]
    pub fn new(context: &'a TfheContext<T, Table, LM>) -> Self {
        Self {
            gadget: NttNtruGadgetEncryptWorkspace::new(context.parameters().poly_length()),
            context,
        }
    }

    /// Generates coefficient-domain client and accumulator secrets accepted by this backend.
    ///
    /// Only the accumulator undergoes rejection sampling for NTT-ring invertibility.
    /// The accepted accumulator must also fit external q for later return-key generation.
    /// The transformed secrets are discarded; use [`Self::try_generate`] when
    /// generating a paired server key so those representations can be reused.
    /// Returns a key-generation error when the bounded search is exhausted.
    ///
    /// Distribution and logical key geometry are established by parameter construction.
    pub fn try_generate_client_key<R>(
        &self,
        rng: &mut R,
    ) -> Result<ClientKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.generate_client_key_with_main(rng)
            .map(|(client, _)| client)
    }

    /// Samples the external secret once, retaining the accepted ring transform and inverse.
    /// Standalone clients discard that temporary; paired setup consumes it without reconversion.
    fn generate_client_key_with_main<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, NttNtruSecretKey<T>), KeyGenerationError> {
        let parameters = self.context.parameters();
        let client = primus_lwe::LweSecretKey::generate(parameters.external_lwe(), rng);
        let (accumulator, transformed) = NttNtruSecretKey::generate_pair(
            parameters.accumulator_ntru(),
            self.context.table(),
            rng,
        )?;
        let client_key = ClientKey::new(client, accumulator);
        // Sampling proves the usual q bound. For unusually small q, check the
        // accepted sample rather than rejecting every key from this distribution.
        if parameters
            .accumulator_ntru()
            .secret_key_sampler()
            .maximum_magnitude()
            > parameters.external_lwe().cipher_modulus_minus_one()
        {
            client_key
                .check_accumulator_return_modulus(parameters.external_lwe().cipher_modulus())?;
        }
        Ok((client_key, transformed))
    }

    /// Generates the configured BR and KS pair.
    /// Validates grouping geometry before sampling the client. Keeps the accepted
    /// accumulator transform and inverse for key generation.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_server_key`]'s noise and representation contracts.
    pub fn try_generate<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError> {
        let layout = self.prepare_blind_rotation()?;
        let (client_key, transformed) = self.generate_client_key_with_main(rng)?;
        let server_key =
            self.generate_server_key_from_transformed(&client_key, transformed, layout, rng);
        Ok((client_key, server_key))
    }

    /// Generates configured BR and KS material for an existing client.
    /// Checks the imported secrets before conversion or sampling; retains its input distribution.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_blind_rotation_key`]'s secret and transform contracts.
    /// BR and KS errors must fit the complete PBS noise budget.
    pub fn try_generate_server_key<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError> {
        client_key.check_compatible(self.context.parameters())?;
        let layout = self.prepare_blind_rotation()?;
        let transformed =
            self.transform_accumulator_secret(client_key.accumulator_ntru_secret_key())?;
        Ok(self.generate_server_key_from_transformed(client_key, transformed, layout, rng))
    }

    /// Prepares the transform and inverse of an imported secret after its caller checks
    /// compatibility with the accumulator. Paired generation already has this representation.
    fn transform_accumulator_secret(
        &self,
        secret: &NtruSecretKey<T>,
    ) -> Result<NttNtruSecretKey<T>, NtruError> {
        let accumulator = self.context.parameters().accumulator_ntru();
        NttNtruSecretKey::try_from_coeff_secret_key(
            secret,
            accumulator.cipher_modulus(),
            self.context.table(),
        )
    }

    /// Encrypts selected BR controls after key compatibility and layout preparation.
    /// The borrowed accumulator representation can also be reused by paired CBS generation.
    fn generate_blind_rotation_key_with_main<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client_key: &ClientKey<T>,
        accumulator_ntt: &NttNtruSecretKey<T>,
        layout: BlindRotationLayout<T>,
        rng: &mut R,
    ) -> BlindRotationKey<T> {
        match layout {
            BlindRotationLayout::Classic => self
                .generate_classic_blind_rotation_key_from_transformed(
                    client_key,
                    accumulator_ntt,
                    rng,
                ),
            BlindRotationLayout::Block(layout) => self.generate_block_blind_rotation_key_with_main(
                client_key,
                accumulator_ntt,
                layout,
                rng,
            ),
        }
    }

    /// Consumes the accepted accumulator transform for BR, then releases it before
    /// allocating return-KS rows. Sampling or validation established client
    /// compatibility and the external-q secret-magnitude bound.
    fn generate_server_key_from_transformed<R>(
        &mut self,
        client_key: &ClientKey<T>,
        accumulator_ntt: NttNtruSecretKey<T>,
        layout: BlindRotationLayout<T>,
        rng: &mut R,
    ) -> ServerKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let blind_rotation =
            self.generate_blind_rotation_key_with_main(client_key, &accumulator_ntt, layout, rng);
        drop(accumulator_ntt);
        let key_switching_key = self.generate_lwe_return_key(client_key, rng);
        ServerKey::new(blind_rotation, key_switching_key)
    }

    /// Generates the configured return rows after the secret pair is sampled or validated,
    /// including the magnitude of the accumulator secret at external q.
    fn generate_lwe_return_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> NtruLweKeySwitchingKey<T> {
        let parameters = self.context.parameters();
        NtruLweKeySwitchingKey::generate(
            client_key.accumulator_ntru_secret_key(),
            parameters.accumulator_ntru().cipher_modulus(),
            client_key.external_lwe_secret_key(),
            parameters.key_switching(),
            rng,
        )
    }

    /// Generates only BR material using this context's configured method and gadgets.
    /// No return or CBS key is generated. Block BR encrypts every bit, plus an
    /// independent dummy per block for `AtMostOne`. The first block uses NLEV for lifting.
    ///
    /// Checks both secret roles but does not require f to fit external q.
    ///
    /// # Correctness
    /// Independently generated components must share the actual secrets and this
    /// context's transform representation. Imported accumulator coefficients inherit
    /// [`NttNtruSecretKey::try_from_coeff_secret_key`]'s numerical requirements.
    /// Budget first-group lifting, later group errors and input quantization,
    /// including coarser ManyLUT rotations.
    ///
    /// # Errors
    /// Rejects incompatible secrets or invalid block geometry before consuming randomness.
    /// Propagates accumulator conversion/invertibility failures before sampling.
    pub fn try_generate_blind_rotation_key<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<BlindRotationKey<T>, KeyGenerationError> {
        client_key.check_blind_rotation_compatible(self.context.parameters())?;
        let layout = self.prepare_blind_rotation()?;
        let transformed =
            self.transform_accumulator_secret(client_key.accumulator_ntru_secret_key())?;
        Ok(self.generate_blind_rotation_key_with_main(client_key, &transformed, layout, rng))
    }

    /// Generates independent `NLEV_f[1]` for public polynomial lifting.
    /// Call only when the compiled lookup table needs a public lift. The supplied
    /// parameters select this material's own decomposition basis and row noise;
    /// no BR, CBS or return material is generated or modified.
    ///
    /// # Errors
    /// Rejects another accumulator ring or an incompatible secret before sampling,
    /// and propagates secret conversion failures.
    ///
    /// # Correctness
    /// The secret must be the actual accumulator secret used by the other keys.
    /// Inherits [`NttNtruSecretKey::try_from_coeff_secret_key`]'s numerical
    /// requirements. Budget decomposition and encryption error for the public
    /// polynomial products; compatible parameters do not prove a decoding margin.
    pub fn try_generate_public_lift_key<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        secret: &NtruSecretKey<T>,
        parameters: &primus_ntru::NlevParameters<T, primus_modulus::BarrettModulus<T>>,
        rng: &mut R,
    ) -> Result<NttNlev<Vec<T>>, KeyGenerationError> {
        self.check_public_lift_parameters(parameters)?;
        self.context
            .parameters()
            .check_accumulator_secret_key(secret)?;
        let transformed = self.transform_accumulator_secret(secret)?;
        Ok(self.generate_public_lift_from_transformed(&transformed, parameters, rng))
    }

    /// Validates independently supplied lift metadata before sampling any key rows.
    pub(crate) fn check_public_lift_parameters(
        &self,
        parameters: &primus_ntru::NlevParameters<T, primus_modulus::BarrettModulus<T>>,
    ) -> Result<(), KeyGenerationError> {
        if parameters.poly_length() != self.context.parameters().poly_length()
            || parameters.encryption_parameters().cipher_modulus_value()
                != self
                    .context
                    .parameters()
                    .accumulator_ntru()
                    .cipher_modulus_value()
        {
            return Err(KeyGenerationError::IncompatiblePublicLiftParameters);
        }
        Ok(())
    }

    /// Reuses the checked accumulator transform in paired generation.
    fn generate_classic_blind_rotation_key_from_transformed<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client_key: &ClientKey<T>,
        transformed: &NttNtruSecretKey<T>,
        rng: &mut R,
    ) -> BlindRotationKey<T> {
        let initializer = self.generate_public_lift_from_transformed(
            transformed,
            self.context.parameters().blind_rotation(),
            rng,
        );
        let data = self.generate_controls(client_key, transformed, rng);
        BlindRotationKey {
            blind_rotation_basis: self.context.parameters().blind_rotation().basis().clone(),
            input_distribution: self.context.parameters().external_lwe().secret_key_distr(),
            controls: Controls::Classic { initializer, data },
        }
    }

    /// Shares direct encryption of one with classic initialization, reusing its transform.
    pub(crate) fn generate_public_lift_from_transformed<R>(
        &mut self,
        accumulator_ntt: &NttNtruSecretKey<T>,
        parameters: &primus_ntru::NlevParameters<T, primus_modulus::BarrettModulus<T>>,
        rng: &mut R,
    ) -> NttNlev<Vec<T>>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let mut initializer = NttNlev::zero(parameters.nlev_len());
        accumulator_ntt.encrypt_nlev_constant_to(
            T::ONE,
            &mut initializer,
            parameters,
            self.context.table(),
            rng,
            &mut self.gadget,
        );
        initializer
    }

    /// Encrypts the first binary bit or ternary pair as NLEV; later bits as NGSW.
    fn generate_controls<R>(
        &mut self,
        client_key: &ClientKey<T>,
        accumulator_ntt: &NttNtruSecretKey<T>,
        rng: &mut R,
    ) -> Vec<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let nlev_len = parameters.blind_rotation().nlev_len();
        let coefficients = client_key.external_lwe_secret_key().as_ref();
        let binary = parameters.external_lwe().secret_key_distr().is_binary();
        let count = coefficients
            .len()
            .checked_mul(if binary { 1 } else { 2 })
            .expect("blind-rotation control count overflow");
        // Controls are signed bit plaintexts, whereas the LWE secret uses residues at q.
        let mut selectors = Zeroizing::new(vec![T::SignedInteger::ZERO; count]);
        if binary {
            for (&coefficient, bit) in coefficients.iter().zip(selectors.iter_mut()) {
                *bit = if coefficient == T::ONE {
                    T::SignedInteger::ONE
                } else {
                    T::SignedInteger::ZERO
                };
            }
        } else {
            let minus_one = parameters.external_lwe().cipher_modulus_minus_one();
            for (&coefficient, pair) in coefficients.iter().zip(selectors.as_chunks_mut::<2>().0) {
                pair[0] = if coefficient == T::ONE {
                    T::SignedInteger::ONE
                } else {
                    T::SignedInteger::ZERO
                };
                pair[1] = if coefficient == minus_one {
                    T::SignedInteger::ONE
                } else {
                    T::SignedInteger::ZERO
                };
            }
        }
        let plaintexts = selectors.as_slice();
        let total_len = plaintexts
            .len()
            .checked_mul(nlev_len)
            .expect("blind-rotation control batch length overflow");
        let mut controls = vec![T::ZERO; total_len];
        let first_count = if parameters.external_lwe().secret_key_distr().is_binary() {
            1
        } else {
            2
        };
        let (first, remaining) = controls.split_at_mut(first_count * nlev_len);
        for (&bit, output) in plaintexts[..first_count]
            .iter()
            .zip(first.chunks_exact_mut(nlev_len))
        {
            accumulator_ntt.encrypt_nlev_constant_to(
                if bit == T::SignedInteger::ONE {
                    T::ONE
                } else {
                    T::ZERO
                },
                &mut NttNlev::new(output),
                parameters.blind_rotation(),
                self.context.table(),
                rng,
                &mut self.gadget,
            );
        }
        accumulator_ntt.encrypt_ngsw_signed_constant_batch_to(
            &plaintexts[first_count..],
            remaining,
            parameters.blind_rotation(),
            self.context.table(),
            rng,
        );
        controls
    }

    /// Checks public grouping geometry before secrets or rows are sampled.
    fn prepare_blind_rotation(&self) -> Result<BlindRotationLayout<T>, KeyGenerationError> {
        let parameters = self.context.parameters();
        Ok(match parameters.blind_rotation_method() {
            BlindRotationMethod::Classic => BlindRotationLayout::Classic,
            BlindRotationMethod::Block => {
                BlindRotationLayout::Block(BlockNtruKeyLayout::try_from_parameters(parameters)?)
            }
        })
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Generates paired client and BR/KS server keys using this context's choices.
    /// Inherits [`KeyGenerator::try_generate`]'s contracts.
    pub fn try_generate_keys<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError> {
        KeyGenerator::new(self).try_generate(rng)
    }

    /// Generates configured server material for independently generated client secrets.
    /// Inherits [`KeyGenerator::try_generate_server_key`]'s contracts.
    pub fn try_generate_server_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError> {
        KeyGenerator::new(self).try_generate_server_key(client_key, rng)
    }
}
