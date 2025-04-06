use std::vec;

use algebra::random::DiscreteGaussian;
use mpc::MPCBackend;
use rand::{prelude::Distribution, Rng};

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
    let polynomial_size = secret_key_share.len();

    let mut batch_mpc_rlwe = BatchMPCRlwe::<Backend::Sharing> {
        a: vec![vec![0; polynomial_size]; count],
        b: vec![Default::default(); count * polynomial_size],
    };
    // count = 2 n l = 2 * 1024 * 8
    // polynomial_size = 2024

    batch_mpc_rlwe.a.iter_mut().for_each(|a| {
        backend.shared_rand_field_elements(a);
    });

    let b = &mut batch_mpc_rlwe.b;

    let start = std::time::Instant::now();

    let chunk_size = 2048 * polynomial_size;
    let mut e: Vec<u64> = vec![0; chunk_size];
    for b_chunk in b.chunks_exact_mut(chunk_size) {
        e.iter_mut()
            .zip(gaussian.sample_iter(&mut *rng))
            .for_each(|(e, res)| *e = res);
        if backend.num_parties() <= 5 {
            backend.all_paries_sends_slice_to_all_parties_sum(&e, chunk_size, b_chunk);
        } else {
            backend.all_paries_sends_slice_to_all_parties_sum_with_prg(&e, chunk_size, b_chunk);
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
