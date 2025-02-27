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
    backend.rand_field_elements(&mut a);

    let e_vec: Vec<Backend::Sharing> = (0..backend.num_parties())
        .map(|i| {
            if i == id {
                let e = gaussian.sample(rng);
                backend.input(Some(e), id).unwrap()
            } else {
                backend.input(None, id).unwrap()
            }
        })
        .collect();

    let mut e = e_vec
        .into_iter()
        .reduce(|x, y| backend.add(x, y).unwrap())
        .unwrap();

    for (s_i, a_i) in shared_secret_key.iter().zip(a.iter()) {
        let temp = backend.mul_const(*s_i, *a_i).unwrap();
        e = backend.add(temp, e).unwrap();
    }

    MPCLwe { a, b: e }
}
