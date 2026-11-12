//! CBS program and material binding, resource ownership and LWE return.

use primus_integer::FheUint;
use primus_ntru::NttNgswCiphertext;
use primus_ntt::{MonomialNttTable, U32NttTable};
use primus_shape::PolyLength;
use primus_tfhe::DecompositionLevelCount;
use primus_tfhe_ntru_ntt::{
    BlindRotationMethod, CbsEvaluator, CircuitBootstrapServerKey, ClientKey, Evaluator, Lwe,
    TfheEvaluationError, circuit_bootstrap::CircuitBootstrapEvaluator,
};
use rand::{SeedableRng, rngs::StdRng};

use super::{Context, RingSelection};
use crate::fixture::{cbs_gadget, config};

/// Reject the GLWE-specific MSB correction even when q/Q and the gadget basis match.
pub(super) fn assert_msb_lookup_is_rejected<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    context: &Context<T, Table>,
    server: &CircuitBootstrapServerKey<T>,
) {
    let input_codec = primus_encoding::RoundedCodec::new(
        T::TWO,
        context.parameters().external_lwe().cipher_modulus(),
    );
    let msb = primus_tfhe::CircuitBootstrapLookupTable::try_from_fn(
        context.parameters().poly_length(),
        &input_codec,
        primus_tfhe::CbsInputEncoding::MsbBoolean,
        context.cbs_parameters().unwrap().gadget().output_basis(),
        context.parameters().accumulator_ntru().cipher_modulus(),
        T::as_from,
    )
    .unwrap();
    assert!(matches!(
        CircuitBootstrapEvaluator::try_with_lookup_table(
            context,
            server.circuit_bootstrap_key(),
            msb
        ),
        Err(TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable)
    ));
}

/// Validate resource identity before any writes, then transfer the original
/// resources to PBS and return the real CMux output at the extraction endpoints.
pub(super) fn check_resources_and_return<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    context: &Context<T, Table>,
    client: &ClientKey<T>,
    server: &CircuitBootstrapServerKey<T>,
    cbs: CbsEvaluator<'_, T, Table>,
    control: &mut NttNgswCiphertext<Vec<T>>,
    input: Lwe<&[T]>,
    ring: &RingSelection<'_, T, Table>,
) {
    let other = Context::<T, Table>::try_from_parameters(context.parameters().clone()).unwrap();
    let mut foreign = server.bootstrap_resources(&other).unwrap();
    let (mut operation, resources) = cbs.into_parts();
    control.as_mut().fill(Default::default());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        operation.circuit_bootstrap_to(input.as_view(), control, &mut foreign);
    }));
    assert!(result.is_err());
    assert!(control.as_ref().iter().all(|v| *v == Default::default()));
    assert!(matches!(
        Evaluator::try_from_resources(context, foreign, server.server_key()),
        Err(TfheEvaluationError::IncompatibleLweReturnKey)
    ));
    let mut pbs = Evaluator::try_from_resources(context, resources, server.server_key()).unwrap();
    let mut returned_ring = context.allocate_lwe_ciphertext();
    let ring_decryptor = context
        .ring_return_decryptor(client.external_lwe_secret_key(), T::as_from(8))
        .unwrap();
    let n = context.parameters().poly_length().get();
    for index in [0, 1, n - 1] {
        pbs.return_ring_at_to(ring.selected.as_view(), index, returned_ring.as_mut_view());
        assert_eq!(
            ring_decryptor.decrypt(returned_ring.as_view()).unwrap(),
            ring.messages[1][index]
        );
    }
    let identity = context
        .pbs_lookup_table_compiler()
        .unwrap()
        .compile_fn(T::as_from)
        .unwrap();
    let returned = pbs.apply_lookup_table(input.as_view(), &identity);
    let decryptor = context
        .pbs_decryptor(client.external_lwe_secret_key())
        .unwrap();
    assert_eq!(
        decryptor.decrypt(returned.as_view()).unwrap(),
        T::as_from(2)
    );
}

/// Equal gadget bases do not make CBS material from another ring compatible.
#[test]
fn default_cbs_rejects_mixed_ring_material() {
    type U32Context = Context<u32, U32NttTable>;
    let pbs = config(BlindRotationMethod::Classic);
    let gadget = cbs_gadget(None);
    let context = U32Context::try_from_pbs_config(pbs)
        .unwrap()
        .try_with_circuit_bootstrap(gadget)
        .unwrap();
    let mut other_pbs = pbs;
    other_pbs.bsk_poly_length = PolyLength::new(64);
    let other = U32Context::try_from_pbs_config(other_pbs)
        .unwrap()
        .try_with_circuit_bootstrap(gadget)
        .unwrap();
    let mut rng = StdRng::seed_from_u64(108);
    let (_, server) = context
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    let (_, other_server) = other.try_generate_circuit_bootstrap_keys(&mut rng).unwrap();

    // BR/KS and the program match this context; only trace/SS use another N.
    let (server, _) = server.into_parts();
    let (_, circuit) = other_server.into_parts();
    let mixed = CircuitBootstrapServerKey::new(server, circuit);
    assert!(matches!(
        context.circuit_bootstrap_evaluator_with_lookup_table(
            &mixed,
            context.compile_cbs_identity().unwrap(),
        ),
        Err(TfheEvaluationError::IncompatibleCircuitBootstrapParameters)
    ));
}

#[test]
fn projection_selection_is_bound_to_cbs_material() {
    use NtruProjectionMethod::*;
    use primus_tfhe_ntru_ntt::circuit_bootstrap::{
        CircuitBootstrapEvaluator, OneHotCircuitBootstrapEvaluator,
    };
    use primus_tfhe_ntru_ntt::{CbsConfig, CbsParameters, NtruProjectionMethod};
    type U32Context = Context<u32, U32NttTable>;
    let pbs = config(BlindRotationMethod::Classic);
    let gadget = cbs_gadget(Some(DecompositionLevelCount::new(2)));
    let plain = U32Context::try_from_pbs_config(pbs).unwrap();
    // The convenience constructor's default is independent of the performance presets.
    let default = U32Context::try_from_pbs_config(pbs)
        .unwrap()
        .try_with_circuit_bootstrap(gadget)
        .unwrap();
    assert_eq!(default.cbs_parameters().unwrap().projection(), Separate);
    for preset in [
        primus_tfhe_ntru_ntt::experimental::CLASSIC_CBS_U64,
        primus_tfhe_ntru_ntt::experimental::CLASSIC_ONE_HOT_U64,
    ] {
        assert_eq!(preset.projection, PairedTrace);
    }
    let mut rng = StdRng::seed_from_u64(107);
    // PBS-only setup must reject CBS key generation before any material is sampled.
    assert!(matches!(
        plain.try_generate_circuit_bootstrap_keys(&mut rng),
        Err(primus_tfhe_ntru::KeyGenerationError::MissingCircuitBootstrapParameters)
    ));
    for projection in [Separate, FusedLastStage, FusedLastThreeStages, PairedTrace] {
        let context = U32Context::try_from_cbs_config(CbsConfig {
            pbs,
            gadget,
            projection,
            fourier_precision: primus_tfhe_ntru::FourierCbsPrecision::ORDINARY,
        })
        .unwrap();
        let (_, server) = context
            .try_generate_circuit_bootstrap_keys(&mut rng)
            .unwrap();
        let key = server.circuit_bootstrap_key();
        assert_eq!(context.cbs_parameters().unwrap().projection(), projection);
        assert_eq!(key.projection_method(), projection);
        context.circuit_bootstrap_evaluator(&server).unwrap();
        context.one_hot_evaluator(&server).unwrap();

        // Same domain/bases, different projection: reject every configured binding.
        let other_method = if projection == Separate {
            PairedTrace
        } else {
            Separate
        };
        let other = U32Context::try_from_cbs_parameters(
            CbsParameters::try_with_config(plain.parameters().clone(), gadget, other_method)
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            other.circuit_bootstrap_evaluator_with_lookup_table(
                &server,
                other.compile_cbs_identity().unwrap(),
            ),
            Err(TfheEvaluationError::IncompatibleCircuitBootstrapKey)
        ));
        assert!(matches!(
            other.one_hot_evaluator(&server),
            Err(primus_tfhe_ntru::OneHotBootstrapError::Evaluation(
                TfheEvaluationError::IncompatibleCircuitBootstrapKey
            ))
        ));
        let codec = other.cbs_parameters().unwrap().input_codec();
        assert!(matches!(
            CircuitBootstrapEvaluator::try_new(&other, key, codec),
            Err(TfheEvaluationError::IncompatibleCircuitBootstrapKey)
        ));
        assert!(matches!(
            CircuitBootstrapEvaluator::try_with_lookup_table(
                &other,
                key,
                other.compile_cbs_identity().unwrap(),
            ),
            Err(TfheEvaluationError::IncompatibleCircuitBootstrapKey)
        ));
        assert!(matches!(
            OneHotCircuitBootstrapEvaluator::try_new(&other, key, codec),
            Err(primus_tfhe_ntru::OneHotBootstrapError::Evaluation(
                TfheEvaluationError::IncompatibleCircuitBootstrapKey
            ))
        ));

        // PBS-only component composition takes the supplied key's algorithm.
        CircuitBootstrapEvaluator::try_new(&plain, key, codec).unwrap();
        CircuitBootstrapEvaluator::try_with_lookup_table(
            &plain,
            key,
            other.compile_cbs_identity().unwrap(),
        )
        .unwrap();
        OneHotCircuitBootstrapEvaluator::try_new(&plain, key, codec).unwrap();
    }
}
