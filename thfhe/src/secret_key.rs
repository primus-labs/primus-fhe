use std::{marker::PhantomData, sync::Arc};

use algebra::NttField;
use mpc::MPCBackend;
use rand::Rng;

use crate::{
    generate_shared_lwe_secret_key, Fp, MPCLweSecretKey, MPCRlweSecretKey, ThFheParameters,
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

    let b_vec: Vec<(Backendq::Sharing, BackendQ::Sharing)> = (0..t)
        .map(|i| {
            if id == i {
                let b = rng.gen_bool(0.5) as u64;
                (
                    backend_q.input(Some(b), id).unwrap(),
                    backend_big_q.input(Some(b), id).unwrap(),
                )
            } else {
                (
                    backend_q.input(None, id).unwrap(),
                    backend_big_q.input(None, id).unwrap(),
                )
            }
        })
        .collect();

    b_vec
        .into_iter()
        .reduce(|(b_q_x, b_big_q_x), (b_q_y, b_big_q_y)| {
            let temp1 = backend_q.add(b_q_x, b_q_y).unwrap();
            let temp2 = backend_q.mul(b_q_x, b_q_y).unwrap();
            let temp3 = backend_q.double(temp2).unwrap();

            let temp4 = backend_big_q.add(b_big_q_x, b_big_q_y).unwrap();
            let temp5 = backend_big_q.mul(b_big_q_x, b_big_q_y).unwrap();
            let temp6 = backend_big_q.double(temp5).unwrap();

            (
                backend_q.sub(temp1, temp3).unwrap(),
                backend_big_q.sub(temp4, temp6).unwrap(),
            )
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
        backend_q.sub(b_q1, b_q2).unwrap(),
        backend_big_q.sub(b_big_q1, b_big_q2).unwrap(),
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

    let b_vec: Vec<Backend::Sharing> = (0..t)
        .map(|i| {
            if id == i {
                backend.input(Some(rng.gen_bool(0.5) as u64), id).unwrap()
            } else {
                backend.input(None, id).unwrap()
            }
        })
        .collect();

    b_vec
        .into_iter()
        .reduce(|b_x, b_y| {
            let temp1 = backend.add(b_x, b_y).unwrap();
            let temp2 = backend.mul(b_x, b_y).unwrap();
            let temp3 = backend.double(temp2).unwrap();
            backend.sub(temp1, temp3).unwrap()
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
    backend.sub(b1, b2).unwrap()
}

/// Boolean fhe's secret keys pack.
///
/// This struct contains the LWE secret key,
/// ring secret key, ntt version ring secret key
/// and boolean fhe's parameters.
#[derive(Clone)]
pub struct SecretKeyPack<Backendq, BackendQ>
where
    Backendq: MPCBackend,
    BackendQ: MPCBackend,
{
    /// LWE secret key
    pub input_lwe_secret_key:
        MPCLweSecretKey<<Backendq as MPCBackend>::Sharing, <BackendQ as MPCBackend>::Sharing>,
    /// LWE secret key
    pub intermediate_lwe_secret_key:
        MPCLweSecretKey<<Backendq as MPCBackend>::Sharing, <BackendQ as MPCBackend>::Sharing>,
    /// rlwe secret key
    pub rlwe_secret_key: MPCRlweSecretKey<<BackendQ as MPCBackend>::Sharing>,
    /// FHE parameters
    pub parameters: ThFheParameters,
    pub ntt_table: Arc<<Fp as NttField>::Table>,
    phantom: PhantomData<(Backendq, BackendQ)>,
}

impl<Backendq, BackendQ> SecretKeyPack<Backendq, BackendQ>
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
        let input_lwe_secret_key_type = parameters.input_lwe_secret_key_type();
        let input_lwe_dimension = parameters.input_lwe_dimension();

        let input_lwe_secret_key: MPCLweSecretKey<
            <Backendq as MPCBackend>::Sharing,
            <BackendQ as MPCBackend>::Sharing,
        > = generate_shared_lwe_secret_key(
            backend_q,
            backend_big_q,
            input_lwe_secret_key_type,
            input_lwe_dimension,
            rng,
        );

        let intermediate_lwe_secret_key = generate_shared_lwe_secret_key(
            backend_q,
            backend_big_q,
            parameters.intermediate_lwe_secret_key_type(),
            parameters.intermediate_lwe_dimension(),
            rng,
        );

        let rlwe_secret_key: MPCRlweSecretKey<<BackendQ as MPCBackend>::Sharing> = {
            let mut temp = input_lwe_secret_key.1.clone();
            temp[1..].reverse();
            temp[1..]
                .iter_mut()
                .for_each(|x| *x = backend_big_q.neg(*x).unwrap());
            MPCRlweSecretKey(temp)
        };

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
