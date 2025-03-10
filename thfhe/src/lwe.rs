use std::thread;

use algebra::random::DiscreteGaussian;
use algebra::Field;
use crossbeam::channel;
use mpc::{DNBackend, MPCBackend};
use network::netio::Participant;
use rand::{prelude::Distribution, Rng};

use crate::{parameter::DEFAULT_128_BITS_PARAMETERS, Fp};

#[derive(Debug, Clone, Default)]
pub struct MPCLwe<Share: Default> {
    pub a: Vec<u64>,
    pub b: Share,
}

impl<Share: Default> MPCLwe<Share> {
    pub fn zero(dimension: usize) -> Self {
        MPCLwe {
            a: vec![0; dimension],
            b: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BatchMPCLwe<Share: Default> {
    pub a: Vec<Vec<u64>>,
    pub b: Vec<Share>,
}

pub fn lwe_send_and_recv_data_all_parties<'a>(
    e: Option<&'a [u64]>,
    len: usize,
    id: u32,
    num_parties: u32,
    num_threshold: u32,
    tx: channel::Sender<Vec<u64>>,
    sender_id: u32,
) {
    const RING_MODULUS: u64 = Fp::MODULUS_VALUE;
    let parameters = &DEFAULT_128_BITS_PARAMETERS;

    let mut temp_backend = DNBackend::<RING_MODULUS>::new(
        id,
        num_parties,
        num_threshold,
        0,
        Participant::from_default(3, 50000 + sender_id * 100),
        parameters.ring_dimension(),
    );
    tx.send(temp_backend.input_slice(e, len, sender_id).unwrap())
        .unwrap();
}

pub fn lwe_send_and_recv_data_all_parties_mul_threads<'a>(
    e: Option<&'a [u64]>,
    len: usize,
    myid: u32,
    num_parties: u32,
    num_threshold: u32,
    tx: channel::Sender<Vec<u64>>,
) {
    thread::scope(|s| {
        for i in 0..num_parties {
            let tx_clone = tx.clone();
            if i == myid {
                s.spawn(move || {
                    lwe_send_and_recv_data_all_parties(
                        e,
                        len,
                        myid,
                        num_parties,
                        num_threshold,
                        tx_clone,
                        i,
                    )
                });
            } else {
                s.spawn(move || {
                    lwe_send_and_recv_data_all_parties(
                        None,
                        len,
                        myid,
                        num_parties,
                        num_threshold,
                        tx_clone,
                        i,
                    )
                });
            }
        }
    });
}

pub fn generate_shared_lwe_ciphertext_vec<Backend, R>(
    backend: &mut Backend,
    shared_secret_key: &[Backend::Sharing],
    count: usize,
    gaussian: DiscreteGaussian<u64>,
    rng: &mut R,
) -> BatchMPCLwe<Backend::Sharing>
where
    Backend: MPCBackend,
    R: Rng,
{
    let id = backend.party_id();

    let mut batch_mpc_lwe = BatchMPCLwe {
        a: vec![vec![0; shared_secret_key.len()]; count],
        b: vec![Default::default(); count],
    };

    batch_mpc_lwe.a.iter_mut().for_each(|a| {
        backend.shared_rand_field_elements(a);
    });

    let b = &mut batch_mpc_lwe.b;
    let e_will_share = gaussian
        .sample_iter(&mut *rng)
        .take(count)
        .collect::<Vec<_>>();
    // for i in 0..backend.num_parties() {
    //     let temp = if i == id {
    //         backend.input_slice(Some(&e_will_share), count, i).unwrap()
    //     } else {
    //         backend.input_slice(None, count, i).unwrap()
    //     };
    //     b.iter_mut().zip(temp.iter()).for_each(|(bi, temp)| {
    //         *bi = backend.add(*bi, *temp);
    //     });
    // }
    let (tx, rx) = channel::unbounded::<Vec<u64>>();
    lwe_send_and_recv_data_all_parties_mul_threads(
        Some(&e_will_share),
        count,
        id,
        backend.num_parties(),
        backend.num_threshold(),
        tx.clone(),
    );
    drop(tx);
    for res in rx.iter() {
        b.iter_mut()
            .zip(res.iter())
            .for_each(|(e, res)| *e = backend.add_const(*e, *res));
    }

    batch_mpc_lwe
        .a
        .iter()
        .zip(batch_mpc_lwe.b.iter_mut())
        .for_each(|(a, b)| {
            let ip = backend.inner_product_const(shared_secret_key, a);
            *b = backend.add(ip, *b);
        });

    batch_mpc_lwe
}

pub fn generate_shared_lwe_ciphertext<Backend, R>(
    backend: &mut Backend,
    shared_secret_key: &[Backend::Sharing],
    gaussian: DiscreteGaussian<u64>,
    rng: &mut R,
) -> MPCLwe<Backend::Sharing>
where
    Backend: MPCBackend,
    R: Rng,
{
    let id = backend.party_id();
    let mut a = vec![0; shared_secret_key.len()];
    backend.shared_rand_field_elements(&mut a);

    let e_wil_share = gaussian.sample(rng);
    let e_vec: Vec<Backend::Sharing> = (0..backend.num_parties())
        .map(|i| {
            if i == id {
                backend.input(Some(e_wil_share), i).unwrap()
            } else {
                backend.input(None, i).unwrap()
            }
        })
        .collect();

    let e = e_vec.into_iter().reduce(|x, y| backend.add(x, y)).unwrap();

    let b = backend.inner_product_const(shared_secret_key, &a);
    let b = backend.add(b, e);

    MPCLwe { a, b }
}
