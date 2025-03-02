use std::{marker::PhantomData, sync::Arc};

use algebra::NttField;
use mpc::MPCBackend;
use rand::Rng;

use crate::{
    generate_shared_lwe_secret_key, generate_shared_rlwe_secret_key, Fp,
    MPCDoubleBackendLweSecretKey, MPCLweSecretKey, MPCRlweSecretKey, ThFheParameters,
};

pub fn generate_shared_binary_value_two_field<Backendq, BackendQ, R>(
    backend_q: &mut Backendq,
    backend_big_q: &mut BackendQ,
    rng: &mut R,
) -> (Backendq::Sharing, BackendQ::Sharing)
where
    Backendq: MPCBackend,
    BackendQ: MPCBackend,
    R: Rng,
{
    let id = backend_q.party_id();
    let t = backend_q.num_threshold();

    let b_vec: Vec<(Backendq::Sharing, BackendQ::Sharing)> = (0..=t)
        .map(|i| {
            if id == i {
                let b = rng.gen_bool(0.5) as u64;
                (
                    backend_q.input(Some(b), i).unwrap(),
                    backend_big_q.input(Some(b), i).unwrap(),
                )
            } else {
                (
                    backend_q.input(None, i).unwrap(),
                    backend_big_q.input(None, i).unwrap(),
                )
            }
        })
        .collect();

    b_vec
        .into_iter()
        .reduce(|(b_q_x, b_big_q_x), (b_q_y, b_big_q_y)| {
            let temp1 = backend_q.add(b_q_x, b_q_y);
            let temp2 = backend_q.mul(b_q_x, b_q_y).unwrap();
            let temp3 = backend_q.double(temp2);

            let temp4 = backend_big_q.add(b_big_q_x, b_big_q_y);
            let temp5 = backend_big_q.mul(b_big_q_x, b_big_q_y).unwrap();
            let temp6 = backend_big_q.double(temp5);

            (backend_q.sub(temp1, temp3), backend_big_q.sub(temp4, temp6))
        })
        .unwrap()
}

pub fn generate_shared_ternary_value_two_field<Backendq, BackendQ, R>(
    backend_q: &mut Backendq,
    backend_big_q: &mut BackendQ,
    rng: &mut R,
) -> (Backendq::Sharing, BackendQ::Sharing)
where
    Backendq: MPCBackend,
    BackendQ: MPCBackend,
    R: Rng,
{
    let (b_q1, b_big_q1) = generate_shared_binary_value_two_field(backend_q, backend_big_q, rng);
    let (b_q2, b_big_q2) = generate_shared_binary_value_two_field(backend_q, backend_big_q, rng);
    (
        backend_q.sub(b_q1, b_q2),
        backend_big_q.sub(b_big_q1, b_big_q2),
    )
}

pub fn generate_shared_binary_value<Backend, R>(
    backend: &mut Backend,
    rng: &mut R,
) -> Backend::Sharing
where
    Backend: MPCBackend,
    R: Rng,
{
    let id = backend.party_id();
    let t = backend.num_threshold();

    let b_vec: Vec<Backend::Sharing> = (0..=t)
        .map(|i| {
            if id == i {
                backend.input(Some(rng.gen_bool(0.5) as u64), i).unwrap()
            } else {
                backend.input(None, i).unwrap()
            }
        })
        .collect();

    b_vec
        .into_iter()
        .reduce(|b_x, b_y| {
            let temp1 = backend.add(b_x, b_y);
            let temp2 = backend.mul(b_x, b_y).unwrap();
            let temp3 = backend.double(temp2);
            backend.sub(temp1, temp3)
        })
        .unwrap()
}

pub fn generate_shared_ternary_value<Backend, R>(
    backend: &mut Backend,
    rng: &mut R,
) -> Backend::Sharing
where
    Backend: MPCBackend,
    R: Rng,
{
    let b1 = generate_shared_binary_value(backend, rng);
    let b2 = generate_shared_binary_value(backend, rng);
    backend.sub(b1, b2)
}

/// Boolean fhe's secret keys pack.
///
/// This struct contains the LWE secret key,
/// ring secret key, ntt version ring secret key
/// and boolean fhe's parameters.
#[derive(Clone)]
pub struct MPCSecretKeyPack<Backendq, BackendQ>
where
    Backendq: MPCBackend,
    BackendQ: MPCBackend,
{
    /// input LWE secret key
    pub input_lwe_secret_key: MPCLweSecretKey<<BackendQ as MPCBackend>::Sharing>,
    /// intermediate LWE secret key
    pub intermediate_lwe_secret_key: MPCDoubleBackendLweSecretKey<
        <Backendq as MPCBackend>::Sharing,
        <BackendQ as MPCBackend>::Sharing,
    >,
    /// rlwe secret key
    pub rlwe_secret_key: MPCRlweSecretKey<<BackendQ as MPCBackend>::Sharing>,
    /// FHE parameters
    pub parameters: ThFheParameters,
    pub ntt_table: Arc<<Fp as NttField>::Table>,
    phantom: PhantomData<(Backendq, BackendQ)>,
}

impl<Backendq, BackendQ> MPCSecretKeyPack<Backendq, BackendQ>
where
    Backendq: MPCBackend,
    BackendQ: MPCBackend,
{
    /// Create a new secret key pack.
    pub fn new<R>(
        backend_q: &mut Backendq,
        backend_big_q: &mut BackendQ,
        parameters: ThFheParameters,
        rng: &mut R,
    ) -> Self
    where
        R: Rng,
    {
        let intermediate_lwe_params = parameters.intermediate_lwe_params();
        let blind_rotation_params = parameters.blind_rotation_params();

        let intermediate_lwe_secret_key: MPCDoubleBackendLweSecretKey<
            Backendq::Sharing,
            BackendQ::Sharing,
        > = generate_shared_lwe_secret_key(
            backend_q,
            backend_big_q,
            intermediate_lwe_params.secret_key_type(),
            intermediate_lwe_params.dimension(),
            rng,
        );

        let rlwe_secret_key: MPCRlweSecretKey<<BackendQ as MPCBackend>::Sharing> =
            generate_shared_rlwe_secret_key(
                backend_big_q,
                blind_rotation_params.secret_key_type,
                blind_rotation_params.dimension,
                rng,
            );

        let input_lwe_secret_key: MPCLweSecretKey<<BackendQ as MPCBackend>::Sharing> =
            MPCLweSecretKey::new(rlwe_secret_key.0.clone());

        // let lwe_sk: Vec<u64> = input_lwe_secret_key
        //     .as_ref()
        //     .iter()
        //     .map(|s| backend_big_q.reveal_to_all(*s).unwrap())
        //     .collect();

        // let rlwe_sk: Vec<u64> = rlwe_secret_key
        //     .0
        //     .iter()
        //     .map(|s| backend_big_q.reveal_to_all(*s).unwrap())
        //     .collect();

        // println!("lwe_sk: {:?}", lwe_sk);
        // println!("rlwe_sk: {:?}", rlwe_sk);
        // assert_eq!(lwe_sk, rlwe_sk);

        // let inter_lwe_sk: Vec<u64> = intermediate_lwe_secret_key
        //     .1
        //     .iter()
        //     .map(|s| backend_big_q.reveal_to_all(*s).unwrap())
        //     .collect();

        // println!("inter_lwe_sk: {:?}", inter_lwe_sk);

        let ntt_table = parameters.generate_ntt_table_for_rlwe();

        Self {
            input_lwe_secret_key,
            intermediate_lwe_secret_key,
            rlwe_secret_key,
            parameters,
            ntt_table: Arc::new(ntt_table),
            phantom: PhantomData,
        }
    }
}
