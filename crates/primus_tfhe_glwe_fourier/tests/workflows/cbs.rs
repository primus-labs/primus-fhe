//! Circuit bootstrapping cases across input encodings and PBS orders.

use primus_fft::FftTable;
use primus_glwe::{BlockOccupancy, GlweDimension, SecretKeyDistr};
use primus_lwe::LweDimension;
use primus_tfhe_glwe_fourier::{BlindRotationMethod, CbsInputEncoding, PbsOrder};

use super::parameters::{config, two_domain_config};
use super::pbs::PbsFixture;

mod selection;

use selection::{CbsCoverage, circuit_selection, circuit_selection_with_trace};

/// Both engines use the same fixed seed and u32 classic/KS-before-BR config.
/// Each engine checks every decoded coefficient against the expected plaintext.
#[test]
fn u32_classic_cbs_rows_and_consumption() {
    let mut config = config(BlindRotationMethod::Classic);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    config.order = PbsOrder::KeyswitchBootstrap;
    #[cfg(feature = "rustfft")]
    circuit_selection::<u32, primus_fft::RustFftTable, _>(config, CbsCoverage::Selection);
    #[cfg(feature = "tfhe-fft")]
    circuit_selection::<u32, primus_fft::TfheFftTable, _>(config, CbsCoverage::Selection);
}

#[test]
fn q1024_classic_returns_and_cbs() {
    fn check<Table: FftTable>() {
        for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
            let config = two_domain_config(BlindRotationMethod::Classic, order);
            let mut fixture = PbsFixture::<u64, Table, _>::new(config);
            fixture.check_chain();
            fixture.check_batches();
            circuit_selection::<u64, Table, _>(config, CbsCoverage::Bindings);
        }
    }
    #[cfg(feature = "rustfft")]
    check::<primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    check::<primus_fft::TfheFftTable>();
}

/// Native32 Block with a separate input q exercises both KS placements for
/// PBS, changing ManyLUT strides, MVB and ordinary CBS.
#[test]
fn u32_block_two_domain_workflows() {
    fn check<Table: FftTable>() {
        for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
            let mut config = two_domain_config::<u32>(BlindRotationMethod::Block, order);
            circuit_selection::<u32, Table, _>(config, CbsCoverage::Selection);
            for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
                config.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
                    block_size: 3,
                    occupancy,
                };
                let mut fixture = PbsFixture::<u32, Table, _>::new(config);
                fixture.check_chain();
                fixture.check_batches();
            }
        }
    }
    #[cfg(feature = "rustfft")]
    check::<primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    check::<primus_fft::TfheFftTable>();
}

/// KS-before-BR prepares the direct-block input, then CBS controls encrypted
/// CMux and coefficient-indexed LWE returns. The logical width need not divide
/// the public zero-padded ring-KS target length.
#[test]
fn u64_block_cbs_and_returns() {
    fn check<Table: FftTable>() {
        let mut config =
            two_domain_config(BlindRotationMethod::Block, PbsOrder::KeyswitchBootstrap);
        config.small_lwe.dimension = LweDimension::new(10);
        for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
            config.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
                block_size: 5,
                occupancy,
            };
            circuit_selection::<u64, Table, _>(config, CbsCoverage::Selection);
        }
    }
    #[cfg(feature = "rustfft")]
    check::<primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    check::<primus_fft::TfheFftTable>();
}

/// Split changes trace alone: preserve both PBS orders, Classic and Block BR and
/// a ternary ring key. The same consumer checks all rows and gadget levels.
#[test]
#[cfg(feature = "split-trace")]
fn split_trace_cbs_workflows() {
    fn check<Table: FftTable>() {
        for method in [BlindRotationMethod::Classic, BlindRotationMethod::Block] {
            for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
                let mut config = config::<u64>(method);
                config.bsk_dimension = GlweDimension::new(1);
                config.order = order;
                circuit_selection_with_trace::<u64, Table, _>(
                    config,
                    CbsInputEncoding::Padded,
                    primus_tfhe_glwe_fourier::FourierTracePrecision::Split35,
                    CbsCoverage::Selection,
                );
            }
        }
    }
    #[cfg(feature = "rustfft")]
    check::<primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    check::<primus_fft::TfheFftTable>();
}

/// A valid split choice must not silently become Ordinary when the feature is off.
#[test]
#[cfg(not(feature = "split-trace"))]
fn split_trace_requires_backend_feature() {
    use super::parameters::decomposition;

    fn check<Table: FftTable>() {
        use primus_tfhe_glwe_fourier::{
            CbsGadgetConfig, CbsParameters, FourierTracePrecision, PbsParameters, TfheContext,
            TfheContextError,
        };
        let mut pbs = config::<u64>(BlindRotationMethod::Classic);
        pbs.bsk_dimension = GlweDimension::new(1);
        let gadget = CbsGadgetConfig {
            trace: decomposition(),
            scheme_switch: decomposition(),
            output: decomposition(),
        };
        let parameters = CbsParameters::try_with_config(
            PbsParameters::try_from_config(pbs).unwrap(),
            gadget,
            CbsInputEncoding::Padded,
            FourierTracePrecision::Split35,
        )
        .unwrap();
        assert!(matches!(
            TfheContext::<u64, Table>::try_from_cbs_parameters(parameters),
            Err(TfheContextError::SplitTraceUnavailable)
        ));
        // Extending an existing PBS Context keeps its table and has the same gate.
        let context = TfheContext::<u64, Table>::try_from_pbs_config(pbs).unwrap();
        assert!(matches!(
            context.try_with_circuit_bootstrap(
                gadget,
                CbsInputEncoding::Padded,
                FourierTracePrecision::Split35,
            ),
            Err(TfheContextError::SplitTraceUnavailable)
        ));
    }
    #[cfg(feature = "rustfft")]
    check::<primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    check::<primus_fft::TfheFftTable>();
}

/// MSB offsets work with either full-trace implementation and both KS placements.
#[test]
fn msb_boolean_cbs() {
    fn check<Table: FftTable>() {
        use primus_tfhe_glwe_fourier::FourierTracePrecision;
        // Native32 and same q=Q remain supported by ordinary trace.
        circuit_selection_with_trace::<u32, Table, _>(
            config(BlindRotationMethod::Classic),
            CbsInputEncoding::MsbBoolean,
            FourierTracePrecision::Ordinary,
            CbsCoverage::Selection,
        );
        for (method, precision) in [
            (
                BlindRotationMethod::Classic,
                FourierTracePrecision::Ordinary,
            ),
            #[cfg(feature = "split-trace")]
            (BlindRotationMethod::Block, FourierTracePrecision::Split35),
        ] {
            for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
                let mut config = two_domain_config::<u64>(method, order);
                config.bsk_dimension = GlweDimension::new(1);
                circuit_selection_with_trace::<u64, Table, _>(
                    config,
                    CbsInputEncoding::MsbBoolean,
                    precision,
                    CbsCoverage::Selection,
                );
            }
        }
    }
    #[cfg(feature = "rustfft")]
    check::<primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    check::<primus_fft::TfheFftTable>();
}
