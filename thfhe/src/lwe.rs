use algebra::random::DiscreteGaussian;
use mpc::{MPCBackend, MPCId};
use rand::{prelude::Distribution, Rng};

pub struct MPCLwe {
    pub a: Vec<u64>,
    pub b: MPCId,
}

pub fn generate_shared_lwe_ciphertext<Backend, R>(
    backend: &mut Backend,
    shared_secret_key: &[MPCId],
    gaussian: DiscreteGaussian<u64>,
    rng: &mut R,
) -> MPCLwe
where
    Backend: MPCBackend,
    R: Rng,
{
    let id = backend.id().0 as u32;
    let a = vec![backend.rand_coin(); shared_secret_key.len()];

    let e_vec: Vec<MPCId> = (0..backend.num_parties())
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
        let temp1 = backend.mul_const(*s_i, *a_i).unwrap();
        e = backend.add(temp1, e).unwrap();
    }

    MPCLwe { a, b: e }
}
