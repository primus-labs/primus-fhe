use std::vec;

use algebra::random::DiscreteGaussian;
use algebra::Field;
use crossbeam::channel;
use mpc::{DNBackend, MPCBackend};
use network::netio::Participant;
use rand::{prelude::Distribution, Rng};

use crate::{parameter::DEFAULT_128_BITS_PARAMETERS, Fp};

pub struct MPCRlwe<Share> {
    pub a: Vec<u64>,
    pub b: Vec<Share>,
}

#[derive(Debug, Clone, Default)]
pub struct BatchMPCRlwe<Share: Default> {
    pub a: Vec<Vec<u64>>,
    pub b: Vec<Share>,
}

#[derive(Debug, Clone, Default)]
pub struct BatchMPCNttRlwe<Share: Default> {
    pub a: Vec<Vec<u64>>,
    pub b: Vec<Share>,
}

pub fn send_and_recv_data_all_parties(
    e: Option<&[u64]>,
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

pub fn send_and_recv_data_all_parties_mul_threads(
    e: Option<&[u64]>,
    len: usize,
    myid: u32,
    num_parties: u32,
    num_threshold: u32,
    tx: channel::Sender<Vec<u64>>,
) {
    std::thread::scope(|s| {
        for i in 0..num_parties {
            let tx_clone = tx.clone();
            if i == myid {
                s.spawn(move || {
                    send_and_recv_data_all_parties(
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
                    send_and_recv_data_all_parties(
                        None,
                        len,
                        myid,
                        num_parties,
                        num_threshold,
                        tx_clone,
                        i,
                    )
                });
            };
        }
    });

    // for i in 0..num_parties {
    //     let tx_clone = tx.clone();
    //     if i == myid {
    //         let send_data = e.clone();
    //         pool.execute(move || {
    //             send_and_recv_data_all_parties(
    //                 Some(&send_data),
    //                 len,
    //                 myid,
    //                 num_parties,
    //                 num_threshold,
    //                 tx_clone,
    //                 i,
    //             )
    //         });
    //     } else {
    //         pool.execute(move || {
    //             send_and_recv_data_all_parties(
    //                 None,
    //                 len,
    //                 myid,
    //                 num_parties,
    //                 num_threshold,
    //                 tx_clone,
    //                 i,
    //             )
    //         });
    //     };
    // }
}

pub fn generate_share_ntt_rlwe_ciphertext_vec<Backend, R>(
    backend: &mut Backend,
    secret_key_share: &[Backend::Sharing],
    ntt_secret_key_share: &[Backend::Sharing],
    count: usize,
    gaussian: DiscreteGaussian<u64>,
    rng: &mut R,
) -> BatchMPCNttRlwe<Backend::Sharing>
where
    Backend: MPCBackend,
    R: Rng,
{
    let id = backend.party_id();

    let polynomial_size = secret_key_share.len();

    let mut batch_mpc_rlwe = BatchMPCRlwe {
        a: vec![vec![0; polynomial_size]; count],
        b: vec![Default::default(); count * polynomial_size],
    };

    batch_mpc_rlwe.a.iter_mut().for_each(|a| {
        backend.shared_rand_field_elements(a);
    });

    let b = &mut batch_mpc_rlwe.b;

    // let e = gaussian
    //     .sample_iter(&mut *rng)
    //     .take(count * polynomial_size)
    //     .collect::<Vec<_>>();

    let start = std::time::Instant::now();
    // for i in 0..backend.num_parties() {
    //     let temp = if i == id {
    //         backend
    //             .input_slice(Some(&e), count * polynomial_size, i)
    //             .unwrap()
    //     } else {
    //         backend
    //             .input_slice(None, count * polynomial_size, i)
    //             .unwrap()
    //     };
    //     b.iter_mut().zip(temp.iter()).for_each(|(e, temp)| {
    //         *e = backend.add(*e, *temp);
    //     });
    // }

    // 使用无界通道来收集线程结果
    // let (tx, rx) = channel::unbounded::<Vec<u64>>();

    // send_and_recv_data_all_parties_mul_threads(
    //     e,
    //     count * polynomial_size,
    //     id,
    //     backend.num_parties(),
    //     backend.num_threshold(),
    //     tx.clone(),
    // );

    // drop(tx);
    // for res in rx.iter() {
    //     b.iter_mut()
    //         .zip(res.iter())
    //         .for_each(|(e, res)| *e = backend.add_const(*e, *res));
    // }

    let chunk_size = 2048 * polynomial_size;
    let mut e = vec![0; chunk_size];
    for b_chunk in b.chunks_exact_mut(chunk_size) {
        let (tx, rx) = channel::unbounded::<Vec<u64>>();
        e.iter_mut()
            .zip(gaussian.sample_iter(&mut *rng))
            .for_each(|(e, res)| *e = res);

        send_and_recv_data_all_parties_mul_threads(
            Some(&e),
            chunk_size,
            id,
            backend.num_parties(),
            backend.num_threshold(),
            tx.clone(),
        );

        drop(tx);
        for res in rx.iter() {
            b_chunk
                .iter_mut()
                .zip(res.iter())
                .for_each(|(e, res)| *e = backend.add_const(*e, *res));
        }
    }

    let end = std::time::Instant::now();
    println!("Share random e takes time: {:?}", end - start);

    batch_mpc_rlwe
        .a
        .iter_mut()
        .zip(batch_mpc_rlwe.b.chunks_mut(polynomial_size))
        .for_each(|(a, b)| {
            backend.ntt_sharing_poly_inplace(b);
            backend.ntt_poly_inplace(a);

            let res = ntt_secret_key_share
                .iter()
                .zip(a.iter())
                .map(|(s, a)| backend.mul_const(*s, *a));

            b.iter_mut().zip(res).for_each(|(b, res)| {
                *b = backend.add(*b, res);
            });
        });

    BatchMPCNttRlwe {
        a: batch_mpc_rlwe.a,
        b: batch_mpc_rlwe.b,
    }
}

pub fn generate_share_rlwe_ciphertext<Backend, R>(
    backend: &mut Backend,
    secret_key_share: &[Backend::Sharing],
    gaussian: DiscreteGaussian<u64>,
    rng: &mut R,
) -> MPCRlwe<Backend::Sharing>
where
    Backend: MPCBackend,
    R: Rng,
{
    let id = backend.party_id();
    let mut a = vec![0; secret_key_share.len()];
    backend.shared_rand_field_elements(&mut a);

    let mut e = vec![Default::default(); secret_key_share.len()];
    let mut e_vec = vec![Default::default(); backend.num_parties() as usize];

    let e_wil_share = gaussian.sample(rng);
    e.iter_mut().for_each(|e_i| {
        e_vec.iter_mut().enumerate().for_each(|(i, eij)| {
            *eij = if i == id as usize {
                backend.input(Some(e_wil_share), i as u32).unwrap()
            } else {
                backend.input(None, i as u32).unwrap()
            };
        });
        *e_i = e_vec
            .iter()
            .copied()
            .reduce(|x, y| backend.add(x, y))
            .unwrap();
    });

    let field = backend.field_modulus_value();

    let neg = |v: &mut u64| {
        if *v != 0 {
            *v = field - *v;
        }
    };
    let mut a_clone = a.clone();
    a_clone[1..].reverse();
    a_clone[1..].iter_mut().for_each(neg);

    e.iter_mut().for_each(|ei| {
        let temp = backend.inner_product_const(secret_key_share, &a_clone);
        *ei = backend.sub(*ei, temp);

        a_clone.rotate_right(1);
        neg(&mut a_clone[0]);
    });

    MPCRlwe { a, b: e }
}
