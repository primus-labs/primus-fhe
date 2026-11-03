use super::{BfvParameters, BfvParametersError};
use primus_decompose::DecompositionBaseLog;
use primus_encoding::{BfvRnsCodec, BfvRnsCodecError, PlaintextEmbedding};
use primus_glwe_rns::{CrtGlweEncryptionParameters, RnsDomainError, SecretKeyDistr};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize};
use primus_modulus::BarrettModulus;
use primus_rns::RNSBase;
use primus_shape::PolyLength;
use std::sync::Arc;

#[test]
fn constructors_check_complete_private_noise_recovery() {
    let moduli = [BarrettModulus::new(97u64)];
    for (gamma, sigma, magnitude, valid) in [
        (13, 1.0, 12, true),
        (13, 1.25, 15, false),
        (101, 1.25, 15, true),
        (101, 1.375, 16, false),
    ] {
        let base = RNSBase::new(&moduli).unwrap();
        let size = RnsGlweSize::new(GlweSize::new(GlweDimension::new(1), PolyLength::new(32)), 1);
        let core = Arc::new(CrtGlweEncryptionParameters::new(
            size,
            &base,
            SecretKeyDistr::UniformBinary,
            sigma,
        ));
        let codec = BfvRnsCodec::new(BarrettModulus::new(3), base, BarrettModulus::new(gamma));
        for result in [
            BfvParameters::try_from_parts(core, codec),
            BfvParameters::try_new(
                PolyLength::new(32),
                BarrettModulus::new(3),
                BarrettModulus::new(gamma),
                &moduli,
                SecretKeyDistr::UniformBinary,
                sigma,
            ),
        ] {
            if valid {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(BfvParametersError::Encoding(
                    BfvRnsCodecError::InsufficientNoiseRecovery {
                        maximum_noise_magnitude,
                        embedding: PlaintextEmbedding::Unsigned,
                    }
                )) if maximum_noise_magnitude == magnitude));
            }
        }
    }
}

#[test]
fn parts_require_rank_one_and_an_identical_ordered_base() {
    let moduli = [97u64, 17].map(BarrettModulus::new);
    let base = RNSBase::new(&moduli).unwrap();
    for rank in [1, 2] {
        let size = RnsGlweSize::new(
            GlweSize::new(GlweDimension::new(rank), PolyLength::new(32)),
            2,
        );
        let core = Arc::new(CrtGlweEncryptionParameters::new(
            size,
            &base,
            SecretKeyDistr::UniformBinary,
            1.0,
        ));
        let codec = BfvRnsCodec::new(
            BarrettModulus::new(3),
            base.clone(),
            BarrettModulus::new(101),
        );
        let result = BfvParameters::try_from_parts(Arc::clone(&core), codec);
        if rank == 2 {
            assert!(matches!(
                result,
                Err(BfvParametersError::Domain(
                    RnsDomainError::DimensionMismatch {
                        expected: 1,
                        actual: 2
                    }
                ))
            ));
        } else {
            let parameters = result.unwrap();
            let gadget = parameters.gadget_parameters(DecompositionBaseLog::new(3), None);
            assert!(std::ptr::eq(
                parameters.encryption_parameters(),
                core.as_ref()
            ));
            assert_eq!(gadget.size().rns_glwe_size(), parameters.size());
            assert!(std::ptr::eq(
                parameters.base_q().moduli_product().0,
                gadget.base_q().moduli_product().0
            ));
            assert!(std::ptr::eq(
                parameters.codec().moduli_values(),
                gadget.cipher_moduli_value()
            ));
            for values in [&[17, 97][..], &[97, 19], &[97]] {
                let foreign = RNSBase::new(
                    &values
                        .iter()
                        .copied()
                        .map(BarrettModulus::new)
                        .collect::<Vec<_>>(),
                )
                .unwrap();
                let codec =
                    BfvRnsCodec::new(BarrettModulus::new(3), foreign, BarrettModulus::new(101));
                assert!(matches!(
                    BfvParameters::try_from_parts(Arc::clone(&core), codec),
                    Err(BfvParametersError::Domain(_))
                ));
            }
        }
    }
}
