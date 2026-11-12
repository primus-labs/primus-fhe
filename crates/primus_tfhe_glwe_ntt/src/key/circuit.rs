//! CBS material composed with the ordinary BR and KS server key.

use primus_glwe::NttGlweSecretKey;
use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;
use primus_reduce::RingContext;

use crate::{
    CbsParameters, ClientKey, KeyGenerationError, KeyGenerator, ServerKey, TfheContext,
    TfheEvaluationError, bootstrap::BootstrapResources, circuit_bootstrap::CircuitBootstrapKey,
};

/// Complete CBS material with one BR key, one KS key and trace/scheme-switch keys.
/// The ordinary server key also serves PBS and downstream LWE returns; CBS
/// resources allocate only the input/BR scratch used by circuit bootstrapping.
pub struct CircuitBootstrapServerKey<T: FheUint> {
    server_key: ServerKey<T>,
    circuit_bootstrap: CircuitBootstrapKey<T>,
}

impl<T: FheUint> CircuitBootstrapServerKey<T> {
    /// Moves existing material into a bundle without copying or checking it.
    /// Binding validates layouts; actual paired secrets and transform identity
    /// remain caller requirements.
    #[must_use]
    pub fn new(server_key: ServerKey<T>, circuit_bootstrap: CircuitBootstrapKey<T>) -> Self {
        Self {
            server_key,
            circuit_bootstrap,
        }
    }

    /// Borrows the BR and KS material for PBS or downstream LWE returns.
    #[must_use]
    pub fn server_key(&self) -> &ServerKey<T> {
        &self.server_key
    }

    /// Borrows the required trace and scheme-switch material.
    #[must_use]
    pub fn circuit_bootstrap_key(&self) -> &CircuitBootstrapKey<T> {
        &self.circuit_bootstrap
    }

    /// Moves out ordinary and CBS material without copying ciphertext buffers.
    #[must_use]
    pub fn into_parts(self) -> (ServerKey<T>, CircuitBootstrapKey<T>) {
        (self.server_key, self.circuit_bootstrap)
    }

    /// Binds CBS input preparation and BR without allocating output-return scratch.
    /// Bind the CBS evaluator separately with [`Self::circuit_bootstrap_key`].
    /// Inherits [`BootstrapResources::try_new`]'s secret/transform requirements.
    pub fn bootstrap_resources<'a, Table, LM: RingContext<T>>(
        &'a self,
        context: &'a TfheContext<T, Table, LM>,
    ) -> Result<BootstrapResources<'a, T, Table>, TfheEvaluationError>
    where
        Table: MonomialNttTable<ValueT = T>,
    {
        context.bootstrap_resources_from_server_key(&self.server_key)
    }
}

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: FheUint,
    LM: RingContext<T>,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Generates a client and complete CBS material, including the ordinary KS key.
    /// Shares the accepted ring representation between BR and CBS, then releases
    /// it before preparing KS.
    ///
    /// # Errors
    /// Missing CBS state and invalid block geometry precede secret sampling.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate`]'s BR/KS contracts and
    /// [`Self::try_generate_circuit_bootstrap_key`]'s CBS noise requirements.
    pub fn try_generate_circuit_bootstrap_keys<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, CircuitBootstrapServerKey<T>), KeyGenerationError> {
        let operation = self
            .context
            .cbs_parameters()
            .ok_or(KeyGenerationError::MissingCircuitBootstrapParameters)?;
        let layout = self.prepare_blind_rotation()?;
        let client = ClientKey::generate(self.context.parameters(), rng);
        let transformed =
            NttGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), self.context.table());
        let server =
            self.generate_circuit_server_with_main(operation, &client, transformed, layout, rng)?;
        Ok((client, server))
    }

    /// Generates the configured CBS bundle for independently supplied client secrets.
    /// Checks compatibility before converting the secret or sampling key rows.
    /// Inherits [`Self::try_generate_circuit_bootstrap_keys`]'s numerical contracts.
    pub fn try_generate_circuit_bootstrap_server_key<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapServerKey<T>, KeyGenerationError> {
        let operation = self
            .context
            .cbs_parameters()
            .ok_or(KeyGenerationError::MissingCircuitBootstrapParameters)?;
        client.check_compatible(self.context.parameters())?;
        let layout = self.prepare_blind_rotation()?;
        let transformed =
            NttGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), self.context.table());
        self.generate_circuit_server_with_main(operation, client, transformed, layout, rng)
    }

    /// The context owns this complete CBS operation; client compatibility and block
    /// geometry are already established. Share one ring transform between BR and
    /// CBS, then release it before transforming the padded small secret for KS.
    fn generate_circuit_server_with_main<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        operation: &CbsParameters<T, LM>,
        client: &ClientKey<T>,
        transformed: NttGlweSecretKey<T>,
        layout: super::BlindRotationLayout,
        rng: &mut R,
    ) -> Result<CircuitBootstrapServerKey<T>, KeyGenerationError> {
        let blind_rotation =
            self.generate_blind_rotation_key_with_main(client, &transformed, layout, rng)?;
        let circuit_bootstrap = self.generate_circuit_bootstrap_key_with_main(
            client.glwe_secret_key(),
            &transformed,
            operation.gadget().clone(),
            rng,
        );
        drop(transformed);
        let key = self.generate_glwe_key_switching_key(
            operation.pbs_parameters().glwe_key_switching(),
            client,
            rng,
        );
        Ok(CircuitBootstrapServerKey::new(
            ServerKey::new(blind_rotation, key),
            circuit_bootstrap,
        ))
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    LM: RingContext<T>,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Generates paired client/CBS keys with one BR and one KS key.
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_keys`]'s contracts.
    pub fn try_generate_circuit_bootstrap_keys<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, CircuitBootstrapServerKey<T>), KeyGenerationError> {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_keys(rng)
    }

    /// Generates a complete CBS bundle for an existing client.
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_server_key`]'s contracts.
    pub fn try_generate_circuit_bootstrap_server_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        client: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapServerKey<T>, KeyGenerationError> {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_server_key(client, rng)
    }
}
