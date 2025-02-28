use std::thread;

use algebra::{decompose::NonPowOf2ApproxSignedBasis, Field};
use fhe_core::{BinaryBlindRotationKey, LwePublicKey};
use mpc::DNBackend;
use network::netio::Participant;
use thfhe::{
    generate_bootstrapping_key, generate_key_switching_key, generate_lwe_public_key,
    generate_shared_lwe_secret_key, generate_shared_rlwe_secret_key, Fp,
    MPCDoubleBackendLweSecretKey, MPCLweSecretKey, DEFAULT_128_BITS_PARAMETERS,
};

const LWE_MODULUS: u64 = 4096;
const RING_MODULUS: u64 = Fp::MODULUS_VALUE;

fn main() {
    const NUM_PARTIES: u32 = 7;
    const THRESHOLD: u32 = 3;
    const BASE_PORT1: u32 = 50000;
    const BASE_PORT2: u32 = 60000;

    let threads = (0..NUM_PARTIES)
        .map(|id| {
            thread::spawn(move || {
                let rng = &mut rand::thread_rng();
                // Setup the DN backend.
                let participants1 = Participant::from_default(NUM_PARTIES, BASE_PORT1);
                let participants2 = Participant::from_default(NUM_PARTIES, BASE_PORT2);
                let mut dn_q =
                    DNBackend::<LWE_MODULUS>::new(id, NUM_PARTIES, THRESHOLD, 20, participants1);
                let mut dn_big_q =
                    DNBackend::<RING_MODULUS>::new(id, NUM_PARTIES, THRESHOLD, 20, participants2);

                let parameters = &DEFAULT_128_BITS_PARAMETERS;

                let input_lwe_params = parameters.input_lwe_params();
                let key_switching_params = parameters.key_switching_params();
                let intermediate_lwe_params = parameters.intermediate_lwe_params();
                let blind_rotation_params = parameters.blind_rotation_params();

                let intermediate_mpc_lwe_secret_key: MPCDoubleBackendLweSecretKey<u64, u64> =
                    generate_shared_lwe_secret_key(
                        &mut dn_q,
                        &mut dn_big_q,
                        intermediate_lwe_params.secret_key_type(),
                        intermediate_lwe_params.dimension(),
                        rng,
                    );

                let mpc_rlwe_secret_key: thfhe::MPCRlweSecretKey<u64> =
                    generate_shared_rlwe_secret_key(
                        &mut dn_big_q,
                        blind_rotation_params.secret_key_type,
                        blind_rotation_params.dimension,
                        rng,
                    );

                let input_mpc_lwe_secret_key: MPCLweSecretKey<u64> =
                    MPCLweSecretKey::new(mpc_rlwe_secret_key.0.clone());

                let kappa = input_lwe_params.dimension
                    * input_lwe_params.cipher_modulus_value.log_modulus() as usize;

                let lwe_public_key: LwePublicKey<u64> = generate_lwe_public_key(
                    &mut dn_big_q,
                    input_mpc_lwe_secret_key.as_ref(),
                    input_lwe_params.noise_distribution(),
                    kappa,
                    rng,
                )
                .into();

                let key_switching_key_basis: NonPowOf2ApproxSignedBasis<u64> =
                    NonPowOf2ApproxSignedBasis::new(
                        blind_rotation_params.modulus,
                        key_switching_params.log_basis,
                        key_switching_params.reverse_length,
                    );

                let key_switching_key = generate_key_switching_key(
                    &mut dn_big_q,
                    input_mpc_lwe_secret_key.as_ref(),
                    intermediate_mpc_lwe_secret_key.1.as_ref(),
                    key_switching_params.noise_distribution_for_Q::<Fp>(),
                    key_switching_key_basis,
                    rng,
                )
                .to_fhe_ksk(key_switching_params, key_switching_key_basis);

                let bootstrapping_key: BinaryBlindRotationKey<Fp> = generate_bootstrapping_key(
                    &mut dn_big_q,
                    intermediate_mpc_lwe_secret_key.1.as_ref(),
                    mpc_rlwe_secret_key.0.as_ref(),
                    blind_rotation_params.noise_distribution(),
                    blind_rotation_params.basis,
                    rng,
                )
                .to_fhe_binary_bsk(blind_rotation_params.dimension);
            })
        })
        .collect::<Vec<_>>();

    for handle in threads {
        handle.join().unwrap();
    }
}
