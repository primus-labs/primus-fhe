//! Circuit bootstrapping cases across input encodings and PBS orders.

use primus_glwe::{BlockOccupancy, GlweDimension, SecretKeyDistr};
use primus_lwe::LweDimension;
use primus_ntt::{U32NttTable, U64NttTable};
use primus_tfhe_glwe_ntt::{
    BlindRotationMethod, CbsConfig, CbsGadgetConfig, CbsInputEncoding, PbsOrder, TfheContext,
};

use super::parameters::{config, decomposition, two_domain_config};
use super::pbs::PbsFixture;

mod selection;

use selection::{CbsCoverage, circuit_selection};

#[test]
fn cbs_rejects_fourier_split_precision() {
    use primus_tfhe_glwe_ntt::{
        CircuitBootstrapParameterError, FourierTracePrecision, TfheContextError, TfheParameterError,
    };
    let mut pbs = config::<u64>(BlindRotationMethod::Classic);
    pbs.bsk_dimension = GlweDimension::new(1);
    let result = TfheContext::<u64, primus_ntt::U64NttTable>::try_from_cbs_config(CbsConfig {
        pbs,
        gadget: CbsGadgetConfig {
            trace: decomposition(),
            scheme_switch: decomposition(),
            output: decomposition(),
        },
        input_encoding: CbsInputEncoding::Padded,
        fourier_trace_precision: FourierTracePrecision::Split35,
    });
    assert!(matches!(
        result,
        Err(TfheContextError::Parameters(
            TfheParameterError::CircuitBootstrap(
                CircuitBootstrapParameterError::UnsupportedSplitTrace
            )
        ))
    ));
}

#[test]
fn u64_classic_cbs() {
    let mut config = config(BlindRotationMethod::Classic);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    config.order = PbsOrder::KeyswitchBootstrap;
    circuit_selection::<u64, U64NttTable, _>(
        config,
        CbsInputEncoding::Padded,
        CbsCoverage::Selection,
    );
}

#[test]
fn q1024_classic_returns_and_cbs() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let config = two_domain_config(BlindRotationMethod::Classic, order);
        let mut fixture = PbsFixture::<u64, U64NttTable, _>::new(config);
        fixture.check_chain();
        fixture.check_batches();
        circuit_selection::<u64, U64NttTable, _>(
            config,
            CbsInputEncoding::Padded,
            CbsCoverage::Bindings,
        );
    }
}

#[test]
fn q1024_fixed_weight_classic_returns_and_cbs_u32() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let mut config = two_domain_config(BlindRotationMethod::Classic, order);
        config.small_lwe.secret_key_distr =
            SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 3 };
        let mut fixture = PbsFixture::<u32, U32NttTable, _>::new(config);
        fixture.check_chain();
        fixture.check_batches();
        circuit_selection::<u32, U32NttTable, _>(
            config,
            CbsInputEncoding::Padded,
            CbsCoverage::Selection,
        );
    }
}

/// The other PBS order prepares input with ring KS, then consumes direct-block
/// CBS controls in encrypted CMux and coefficient-indexed LWE returns.
#[test]
fn u64_block_cbs_and_returns() {
    let mut config = two_domain_config(BlindRotationMethod::Block, PbsOrder::KeyswitchBootstrap);
    config.small_lwe.dimension = LweDimension::new(10);
    for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
        config.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
            block_size: 5,
            occupancy,
        };
        circuit_selection::<u64, U64NttTable, _>(
            config,
            CbsInputEncoding::Padded,
            CbsCoverage::Selection,
        );
    }
}

/// Both orders use an independent q; Classic ternary and Block binary share the
/// MSB program/consumer contract. Existing padded tests retain u32/u64 coverage.
#[test]
fn msb_boolean_cbs() {
    // Same odd q=Q and the narrower coefficient word use the same program contract.
    circuit_selection::<u32, U32NttTable, _>(
        config(BlindRotationMethod::Classic),
        CbsInputEncoding::MsbBoolean,
        CbsCoverage::Selection,
    );
    for method in [BlindRotationMethod::Classic, BlindRotationMethod::Block] {
        for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
            circuit_selection::<u64, U64NttTable, _>(
                two_domain_config(method, order),
                CbsInputEncoding::MsbBoolean,
                CbsCoverage::Selection,
            );
        }
    }
}
