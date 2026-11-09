//! CBS material composed with the ordinary BR and KS server key.

use primus_integer::FheUint;
use primus_ntru::NttNtruSecretKey;
use primus_ntt::MonomialNttTable;

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
    pub fn bootstrap_resources<'a, Table, LM>(
        &'a self,
        context: &'a TfheContext<T, Table, LM>,
    ) -> Result<BootstrapResources<'a, T, Table>, TfheEvaluationError>
    where
        Table: MonomialNttTable<ValueT = T>,
        LM: primus_reduce::RingContext<T>,
    {
        context.bootstrap_resources(self.server_key.blind_rotation_key())
    }
}

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
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
    /// Inherits [`Self::try_generate`]'s BR/KS contracts, the noise requirements of
    /// [`CbsGadgetParameters`](crate::circuit_bootstrap::CbsGadgetParameters), and the
    /// selected projection's residual/noise requirements (see [`crate::NtruProjectionMethod`]).
    pub fn try_generate_circuit_bootstrap_keys<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, CircuitBootstrapServerKey<T>), KeyGenerationError> {
        let operation = self
            .context
            .cbs_parameters()
            .ok_or(KeyGenerationError::MissingCircuitBootstrapParameters)?;
        let sparse_layout = self.prepare_blind_rotation()?;
        let (client, transformed) = self.generate_client_key_with_main(rng)?;
        let server = self.generate_circuit_server_with_main(
            operation,
            &client,
            transformed,
            sparse_layout,
            rng,
        )?;
        Ok((client, server))
    }

    /// Generates configured CBS/return keys and optional independent `NLEV[1]`.
    /// Sparse lookup requests this lift when all input chunks select coefficients;
    /// classic reuses its initializer. Lift metadata is checked before sampling.
    /// Reuses the accepted ring transform and inverse across all generated material.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_circuit_bootstrap_keys`] and
    /// [`Self::try_generate_public_lift_key`]'s noise and representation contracts.
    #[allow(clippy::type_complexity)] // Independently reusable key owners, with no extra bundle.
    pub fn try_generate_circuit_bootstrap_keys_with_public_lift<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        public_lift: Option<&primus_ntru::NlevParameters<T, primus_modulus::BarrettModulus<T>>>,
        rng: &mut R,
    ) -> Result<
        (
            ClientKey<T>,
            CircuitBootstrapServerKey<T>,
            Option<primus_ntru::NttNlevCiphertext<Vec<T>>>,
        ),
        KeyGenerationError,
    > {
        let operation = self
            .context
            .cbs_parameters()
            .ok_or(KeyGenerationError::MissingCircuitBootstrapParameters)?;
        if let Some(parameters) = public_lift {
            self.check_public_lift_parameters(parameters)?;
        }
        let sparse_layout = self.prepare_blind_rotation()?;
        let (client, transformed) = self.generate_client_key_with_main(rng)?;
        // Retain the accepted representation until every ring key has been generated;
        // do not convert f or compute its inverse again solely for the extra lift.
        let lift = public_lift.map(|parameters| {
            self.generate_public_lift_from_transformed(&transformed, parameters, rng)
        });
        let server = self.generate_circuit_server_with_main(
            operation,
            &client,
            transformed,
            sparse_layout,
            rng,
        )?;
        Ok((client, server, lift))
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
        let sparse_layout = self.prepare_blind_rotation()?;
        let transformed = NttNtruSecretKey::try_from_coeff_secret_key(
            client.accumulator_ntru_secret_key(),
            self.context
                .parameters()
                .accumulator_ntru()
                .cipher_modulus(),
            self.context.table(),
        )?;
        self.generate_circuit_server_with_main(operation, client, transformed, sparse_layout, rng)
    }

    /// The context owns this complete CBS operation; client compatibility, the
    /// external-q magnitude bound and sparse geometry are already established.
    /// Share the accepted transform and inverse across BR/CBS, then release them
    /// before allocating coefficient-domain Q→q return-key rows.
    fn generate_circuit_server_with_main<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        operation: &CbsParameters<T, LM>,
        client: &ClientKey<T>,
        transformed: NttNtruSecretKey<T>,
        sparse_layout: Option<crate::sparse::SparseKeyLayout>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapServerKey<T>, KeyGenerationError> {
        let blind_rotation =
            self.generate_blind_rotation_key_with_main(client, &transformed, sparse_layout, rng)?;
        let circuit_bootstrap = self.generate_circuit_bootstrap_key_with_main(
            client.accumulator_ntru_secret_key(),
            &transformed,
            operation,
            rng,
        );
        drop(transformed);
        let parameters = operation.pbs_parameters();
        let key = primus_ntru::NtruLweKeySwitchingKey::generate(
            client.accumulator_ntru_secret_key(),
            parameters.accumulator_ntru().cipher_modulus(),
            client.external_lwe_secret_key(),
            parameters.key_switching(),
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
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
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
