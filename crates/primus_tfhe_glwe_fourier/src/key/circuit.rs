//! CBS material composed with the ordinary BR and KS server key.

use primus_fft::{FftTable, TorusFftValue};
use primus_glwe::FourierGlweEncryptor;
use primus_reduce::RingContext;

use crate::{
    CbsParameters, ClientKey, KeyGenerationError, KeyGenerator, ServerKey, TfheContext,
    TfheEvaluationError, bootstrap::BootstrapResources, circuit_bootstrap::CircuitBootstrapKey,
};

/// Complete CBS material with one BR key, one KS key and trace/scheme-switch keys.
/// The ordinary server key also serves PBS and downstream LWE returns; CBS
/// resources allocate only the input/BR scratch used by circuit bootstrapping.
pub struct CircuitBootstrapServerKey<T: TorusFftValue> {
    server_key: ServerKey<T>,
    circuit_bootstrap: CircuitBootstrapKey<T>,
}

impl<T: TorusFftValue> CircuitBootstrapServerKey<T> {
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
        Table: FftTable,
    {
        context.bootstrap_resources_from_server_key(&self.server_key)
    }
}

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: TorusFftValue,
    LM: RingContext<T>,
    Table: FftTable,
{
    /// Generates a client and complete CBS material, including the ordinary KS key.
    /// Shares the accepted ring representation between BR and CBS, then releases
    /// it before preparing KS. Sparse matching retries only the public map.
    ///
    /// # Errors
    /// Missing CBS state and invalid sparse choices precede secret sampling.
    /// Propagates secret-generation, return-domain and matching failures.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate`]'s BR/KS contracts and
    /// [`Self::try_generate_circuit_bootstrap_key`]'s CBS noise requirements.
    pub fn try_generate_circuit_bootstrap_keys<R>(
        &mut self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, CircuitBootstrapServerKey<T>), KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let operation = self
            .context
            .cbs_parameters()
            .ok_or(KeyGenerationError::MissingCircuitBootstrapParameters)?;
        let sparse_layout = self.prepare_blind_rotation()?;
        let client = ClientKey::generate(self.context.parameters(), rng);
        let encryptor = FourierGlweEncryptor::try_new(
            client.glwe_secret_key(),
            self.context
                .parameters()
                .blind_rotation_params()
                .encryption_parameters(),
        )
        .map_err(crate::error::glwe_encryption_error)?;
        let server = self.generate_circuit_server_with_accumulator(
            operation,
            &client,
            encryptor,
            sparse_layout,
            rng,
        )?;
        Ok((client, server))
    }

    /// Generates the configured CBS bundle for independently supplied client secrets.
    /// Checks compatibility before converting the secret or sampling key rows.
    /// Inherits [`Self::try_generate_circuit_bootstrap_keys`]'s numerical contracts.
    pub fn try_generate_circuit_bootstrap_server_key<R>(
        &mut self,
        client: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let operation = self
            .context
            .cbs_parameters()
            .ok_or(KeyGenerationError::MissingCircuitBootstrapParameters)?;
        client.check_compatible(self.context.parameters())?;
        let sparse_layout = self.prepare_blind_rotation()?;
        let encryptor = FourierGlweEncryptor::try_new(
            client.glwe_secret_key(),
            self.context
                .parameters()
                .blind_rotation_params()
                .encryption_parameters(),
        )
        .map_err(crate::error::glwe_encryption_error)?;
        self.generate_circuit_server_with_accumulator(
            operation,
            client,
            encryptor,
            sparse_layout,
            rng,
        )
    }

    /// The context owns this complete CBS operation; client compatibility and sparse
    /// geometry are already established. Share one coefficient encryption setup between BR and
    /// CBS, then release it before preparing the padded small secret for KS.
    fn generate_circuit_server_with_accumulator<R>(
        &mut self,
        operation: &CbsParameters<T, LM>,
        client: &ClientKey<T>,
        mut encryptor: FourierGlweEncryptor<'_, T>,
        sparse_layout: Option<crate::sparse::SparseKeyLayout>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let blind_rotation = self.generate_blind_rotation_key_with_accumulator(
            client,
            &mut encryptor,
            sparse_layout,
            rng,
        )?;
        let circuit_bootstrap = self.generate_circuit_bootstrap_key_with_accumulator(
            client.glwe_secret_key(),
            &mut encryptor,
            operation.gadget().clone(),
            rng,
        );
        drop(encryptor);
        let key = self.generate_glwe_key_switching_key(
            operation.pbs_parameters().glwe_key_switching(),
            client,
            rng,
        )?;
        Ok(CircuitBootstrapServerKey::new(
            ServerKey::new(blind_rotation, key),
            circuit_bootstrap,
        ))
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    LM: RingContext<T>,
    Table: FftTable,
{
    /// Generates paired client/CBS keys with one BR and one KS key.
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_keys`]'s contracts.
    pub fn try_generate_circuit_bootstrap_keys<R>(
        &self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, CircuitBootstrapServerKey<T>), KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_keys(rng)
    }

    /// Generates a complete CBS bundle for an existing client.
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_server_key`]'s contracts.
    pub fn try_generate_circuit_bootstrap_server_key<R>(
        &self,
        client: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_server_key(client, rng)
    }
}
