use algebra::random::DiscreteGaussian;
use mpc::MPCBackend;
use rand::{prelude::Distribution, Rng};

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

pub fn generate_shared_lwe_ciphertext_vec<Backend, R>(
    backend: &mut Backend,
    shared_secret_key: &[Backend::Sharing],
    count: usize,
    gaussian: &DiscreteGaussian<u64>,
    rng: &mut R,
) -> BatchMPCLwe<Backend::Sharing>
where
    Backend: MPCBackend,
    R: Rng,
{
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

    backend.all_paries_sends_slice_to_all_parties_sum(&e_will_share, count, b);

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
    gaussian: &DiscreteGaussian<u64>,
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
