use algebra::random::DiscreteGaussian;
use mpc::MPCBackend;
use rand::{prelude::Distribution, Rng};

pub struct MPCLwe<Share> {
    pub a: Vec<u64>,
    pub b: Share,
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

    let e_vec: Vec<Backend::Sharing> = (0..backend.num_parties())
        .map(|i| {
            if i == id {
                let e = gaussian.sample(rng);
                // let e: u64 = 0;
                backend.input(Some(e), i).unwrap()
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
