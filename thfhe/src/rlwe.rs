use algebra::random::DiscreteGaussian;
use mpc::{MPCBackend, MPCId};
use rand::{prelude::Distribution, Rng};

pub struct MPCRlwe {
    pub a: Vec<u64>,
    pub b: Vec<MPCId>,
}

pub fn generate_share_rlwe_ciphertext<Backend, R>(
    backend: &mut Backend,
    secret_key_share: &[MPCId],
    gaussian: DiscreteGaussian<u64>,
    rng: &mut R,
) -> MPCRlwe
where
    Backend: MPCBackend,
    R: Rng,
{
    let id = backend.id().0 as u32;
    let field = backend.field_modulus();
    let mut a = vec![backend.rand_coin(); secret_key_share.len()];

    let mut e = vec![MPCId(0); secret_key_share.len()];
    let mut e_vec = vec![MPCId(0); backend.num_parties() as usize];

    e.iter_mut().for_each(|e_i| {
        e_vec.iter_mut().enumerate().for_each(|(i, eij)| {
            *eij = if i == id as usize {
                let e = gaussian.sample(rng);
                backend.input(Some(e), id).unwrap()
            } else {
                backend.input(None, id).unwrap()
            };
        });
        *e_i = e_vec
            .iter()
            .copied()
            .reduce(|x, y| backend.add(x, y).unwrap())
            .unwrap();
    });

    a[1..].reverse();
    a[1..].iter_mut().for_each(|ai| {
        *ai = field - *ai;
    });

    e.iter_mut().enumerate().for_each(|(i, ei)| {
        let mut temp = *ei;
        secret_key_share
            .iter()
            .zip(a.iter())
            .for_each(|(s_i, a_i)| {
                let temp1 = backend.mul_const(*s_i, *a_i).unwrap();
                temp = backend.add(temp1, temp).unwrap();
            });
        *ei = temp;

        if i == secret_key_share.len() - 1 {
            a.rotate_right(1);
            a[0] = field - a[0];
        }
    });

    MPCRlwe { a, b: e }
}
