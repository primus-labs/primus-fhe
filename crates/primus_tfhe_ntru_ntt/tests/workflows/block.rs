//! Block controls, occupancy and cross-operation workflows.

use primus_integer::FheUint;
use primus_lattice::{
    nlev::NlevIter,
    ntru::{Ntru, NttNtru},
};
use primus_modulus::PowOf2Modulus;
use primus_ntru::{BlockOccupancy, LweDimension, SecretKeyDistr};
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_reduce::{EncodeSigned, ReduceAdd, ReduceMul};
use primus_tfhe_ntru_ntt::{
    BlindRotationMethod, ClientKey, NtruProjectionMethod, TfheContext,
    block::BlockNtruBootstrappingKey,
};
use rand::rngs::StdRng;

use super::{cbs::circuit_selection, fixture::config, pbs::check_pbs_workflows};

/// Replays the coefficient-noise sampler in key order to check the exact phase
/// of every generated control. The first block has constant NLEV phases and
/// later NGSW phases contain the full ring secret, including for dummy rows.
pub(super) fn check_block_key_phases<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    context: &TfheContext<T, Table, PowOf2Modulus<T>>,
    client: &ClientKey<T>,
    key: &BlockNtruBootstrappingKey<T>,
    mut rng: StdRng,
) {
    let gadget = context.parameters().blind_rotation();
    let parameters = gadget.encryption_parameters();
    let modulus = parameters.cipher_modulus();
    let table = context.table();
    let n = parameters.poly_length().get();
    let secret = client.accumulator_ntru_secret_key();
    let transformed =
        primus_ntru::NttNtruSecretKey::try_from_coeff_secret_key(secret, modulus, table).unwrap();
    let mut row = NttNtru::<Vec<T>>::zero(n);
    let mut phase = Polynomial::new(vec![T::ZERO; n]);
    let mut expected = vec![T::ZERO; n];
    let support = client.external_lwe_secret_key().as_ref();
    for (block, (range, controls, dummy)) in key.blocks().enumerate() {
        let bits = &support[range];
        let dummy_bit = T::as_from(usize::from(bits.iter().all(|&bit| bit == T::ZERO)));
        let rows = NlevIter::new(controls, gadget.nlev_len())
            .chain(NlevIter::new(dummy, gadget.nlev_len()));
        for (control, bit) in rows.zip(
            bits.iter()
                .copied()
                .chain((!dummy.is_empty()).then_some(dummy_bit)),
        ) {
            for (coefficients, scalar) in control.iter_ntru(n).zip(gadget.basis().scalar_iter()) {
                Ntru::new(coefficients.as_ref()).write_ntt_form(&mut row, table);
                transformed.decrypt_phase_to(&row, &mut phase, modulus, table);
                parameters
                    .noise_distribution()
                    .sample_to(&mut expected, &mut rng);
                let weight = modulus.reduce_mul(bit, scalar);
                if block == 0 {
                    expected[0] = modulus.reduce_add(expected[0], weight);
                } else {
                    for (value, &s) in expected.iter_mut().zip(secret.as_slice()) {
                        *value = modulus.reduce_add(
                            *value,
                            modulus.reduce_mul(weight, modulus.encode_signed(s)),
                        );
                    }
                }
                assert_eq!(phase.as_ref(), expected);
            }
        }
    }
}

/// Direct blocks retain independent q/Q, ordinary PBS, changing interleaved
/// strides and factorized returns.
#[test]
fn u32_block_pbs_and_batches() {
    for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
        let mut config = config(BlindRotationMethod::Block);
        config.external_lwe.dimension = LweDimension::new(6);
        config.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
            block_size: 3,
            occupancy,
        };
        check_pbs_workflows::<u32, U32NttTable>(config);
        circuit_selection::<u32, U32NttTable>(config, NtruProjectionMethod::Separate);
    }
}

/// Wider odd blocks exercise paired aggregation plus its trailing selector.
/// Consume ordinary and one-hot controls, then return real CMux results to LWE.
#[test]
fn u64_block_workflows() {
    for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
        let mut config = config(BlindRotationMethod::Block);
        config.external_lwe.dimension = LweDimension::new(10);
        config.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
            block_size: 5,
            occupancy,
        };
        check_pbs_workflows::<u64, U64NttTable>(config);
        circuit_selection::<u64, U64NttTable>(config, NtruProjectionMethod::PairedTrace);
    }
}
