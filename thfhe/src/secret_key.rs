use std::{marker::PhantomData, sync::Arc};

use algebra::{reduce::*, NttField};
use mpc::MPCBackend;

use crate::{
    generate_shared_lwe_secret_key, generate_shared_rlwe_secret_key, Fp, MPCLweSecretKey,
    MPCRlweSecretKey, ThFheParameters,
};

/// Thfhe's secret keys pack.
///
/// This struct contains the LWE secret key,
/// ring secret key, ntt version ring secret key
/// and thfhe's parameters.
#[derive(Clone)]
pub struct MPCSecretKeyPack<Backend>
where
    Backend: MPCBackend,
{
    /// input LWE secret key
    pub input_lwe_secret_key: MPCLweSecretKey<<Backend as MPCBackend>::Sharing>,
    /// intermediate LWE secret key
    pub intermediate_lwe_secret_key: MPCLweSecretKey<<Backend as MPCBackend>::Sharing>,
    /// rlwe secret key
    pub rlwe_secret_key: MPCRlweSecretKey<<Backend as MPCBackend>::Sharing>,
    /// FHE parameters
    pub parameters: ThFheParameters,
    pub ntt_table: Arc<<Fp as NttField>::Table>,
    phantom: PhantomData<Backend>,
}

impl<Backend> MPCSecretKeyPack<Backend>
where
    Backend: MPCBackend,
{
    /// Create a new secret key pack.
    pub fn new(backend: &mut Backend, parameters: ThFheParameters) -> Self {
        let id = backend.party_id();

        let start = std::time::Instant::now();
        let intermediate_lwe_params = parameters.intermediate_lwe_params();
        let intermediate_lwe_secret_key: MPCLweSecretKey<Backend::Sharing> =
            generate_shared_lwe_secret_key(
                backend,
                intermediate_lwe_params.secret_key_type(),
                intermediate_lwe_params.dimension(),
            );
        println!(
            "Party {} had generated the intermediate lwe secret key with time {:?}",
            id,
            start.elapsed()
        );

        let start = std::time::Instant::now();
        let blind_rotation_params = parameters.blind_rotation_params();
        let rlwe_secret_key: MPCRlweSecretKey<<Backend as MPCBackend>::Sharing> =
            generate_shared_rlwe_secret_key(
                backend,
                blind_rotation_params.secret_key_type,
                blind_rotation_params.dimension,
            );
        println!(
            "Party {} had generated the rlwe secret key with time {:?}",
            id,
            start.elapsed()
        );

        let input_lwe_secret_key: MPCLweSecretKey<<Backend as MPCBackend>::Sharing> =
            MPCLweSecretKey::new(rlwe_secret_key.0.clone());

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

pub fn generate_shared_binary_slices<Backend>(
    backend: &mut Backend,
    length: usize,
) -> Vec<Backend::Sharing>
where
    Backend: MPCBackend,
{
    let random_elements = backend.create_random_elements(length);

    let square = backend
        .double_mul_element_wise(&random_elements, &random_elements)
        .unwrap();

    let square = backend.reveal_slice_to_all(&square).unwrap();

    let modulus = backend.modulus();

    let inv_two = modulus.reduce_inv(2);

    let sqrt = square
        .iter()
        .map(|&x| sqrt_mod_p(x, modulus))
        .collect::<Vec<_>>();

    let mut c = sqrt
        .iter()
        .zip(random_elements.iter())
        .map(|(&x, &y)| backend.mul_const(y, modulus.reduce_inv(x)))
        .collect::<Vec<_>>();
    c.iter_mut().for_each(|x| *x = backend.add_const(*x, 1));
    c.iter_mut()
        .for_each(|x| *x = backend.mul_const(*x, inv_two));

    c
}

pub fn generate_shared_ternary_slices<Backend>(
    backend: &mut Backend,
    length: usize,
) -> Vec<Backend::Sharing>
where
    Backend: MPCBackend,
{
    let mut b = generate_shared_binary_slices(backend, length * 2);
    let (front, end) = b.split_at_mut(length);
    front
        .iter_mut()
        .zip(end.iter_mut())
        .for_each(|(x, y)| *x = backend.sub(*x, *y));
    b.truncate(length);
    b
}

/// 费马小定理方法 (适用于 p ≡ 3 mod 4)
fn sqrt_mod_p_fermat<M: FieldReduce<u64>>(a: u64, p: M) -> u64 {
    p.reduce_exp(a, (p.modulus_minus_one() + 2) / 4)
}

/// Tonelli-Shanks 算法 (适用于 p ≡ 1 mod 4)
fn sqrt_mod_p_tonelli_shanks<M: FieldReduce<u64>>(a: u64, p: M) -> u64 {
    let modulus_minus_one = p.modulus_minus_one();
    let mut q = p.modulus_minus_one();
    let mut s = 0;

    s += q.trailing_zeros();
    q >>= q.trailing_zeros();

    let mut z = 2;
    while p.reduce_exp(z, modulus_minus_one / 2) == 1 {
        z += 1;
    }

    let mut m = s;
    let mut c = p.reduce_exp(z, q);
    let mut t = p.reduce_exp(a, q);
    let mut r = p.reduce_exp(a, (q + 1) / 2);

    while t != 1 {
        let mut i = 0;
        let mut temp = t;
        while temp != 1 {
            p.reduce_square_assign(&mut temp);
            i += 1;
        }

        let b = p.reduce_exp_power_of_2(c, m - i - 1);

        p.reduce_mul_assign(&mut r, b);
        c = p.reduce_square(b);
        p.reduce_mul_assign(&mut t, c);

        m = i;
    }

    r
}

/// 计算平方根
fn sqrt_mod_p<M: FieldReduce<u64>>(a: u64, p: M) -> u64 {
    if p.modulus_minus_one() & 0b11 == 0b10 {
        sqrt_mod_p_fermat(a, p)
    } else {
        sqrt_mod_p_tonelli_shanks(a, p)
    }
}
