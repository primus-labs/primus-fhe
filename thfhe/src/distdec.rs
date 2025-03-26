use algebra::modulus::PowOf2Modulus;
use algebra::reduce::Reduce;
use algebra::Field;
use mpc::MPCBackend;
use rand::Rng;
use std::time::Instant;
use std::u64;

use crate::parameter::{Fp, DEFAULT_128_BITS_PARAMETERS};

pub fn distdec<Backend, R>(
    backend: &mut Backend,
    rng: &mut R,
    a: &Vec<Vec<u64>>,
    b: &Vec<u64>,
    shared_secret_key: &[Backend::Sharing],
) -> Option<Vec<u64>>
where
    Backend: MPCBackend,
    R: Rng,
{
    let q: u64 = Fp::MODULUS_VALUE;
    let parameters = &DEFAULT_128_BITS_PARAMETERS;
    let p = parameters.lwe_plain_modulus();

    let len_p = (p as f64).log2().floor() as u64 + 1;
    let len_q = (q as f64).log2().floor() as u64 + 1;

    let rho: u64 = (2 as u64).pow(len_q as u32);

    let v_delta: u64 = rho / p;

    let start = Instant::now();
    //generate r over rho and r over vdelta
    let eda_elements = generate_eda_elements(
        backend,
        rng,
        len_p,
        (v_delta as f64).log2() as u64,
        b.len() as u64,
    );
    let duration = start.elapsed();
    println!(
        "DD offline, prepare {} eda elements, Time elapsed: {} ns",
        b.len(),
        duration.as_nanos()
    );

    let start = Instant::now();

    //  convert shamir to additive over F_q
    let additive_shares = backend.shamir_secrets_to_additive_secrets(shared_secret_key);

    let v_delta_mod = <PowOf2Modulus<u64>>::new(v_delta);
    let rho_mod = <PowOf2Modulus<u64>>::new(rho);

    let mut res_vec: Vec<u64> = Vec::new();
    let mut u_prime_shares_vec: Vec<u64> = Vec::new();
    for ((ax, bx), (cx, _)) in a.iter().zip(b.iter()).zip(eda_elements.iter()) {
        //as mod q
        let a_mul_s_sum = backend.inner_product_additive_const_p(ax, &additive_shares);

        // m_add_e = b-as mod q
        let m_add_e_shares: u64 = backend.sub_additive_const_p(*bx, a_mul_s_sum);

        //modulus switch
        let u_prime_shares = ((rho as f64) * (m_add_e_shares as f64 / q as f64)).round() as u64;
        u_prime_shares_vec.push(u_prime_shares);
        // exact e shares over vdelta
        res_vec.push(v_delta_mod.reduce(u_prime_shares) + cx);
    }

    // compute e_prime_shares + r_shares over v_delta and reveal
    let res: Vec<u64> = backend
        .reveal_slice_to_all_z2k(&res_vec)
        .iter()
        .map(|x| v_delta_mod.reduce(*x))
        .collect();

    // let real_res = if res > v_delta/2{
    //     res +  rho-v_delta
    // }else{
    //     res
    // };

    let real_res: Vec<u64> = res
        .iter()
        .zip(eda_elements.iter())
        .zip(u_prime_shares_vec.iter())
        .map(|((ax, (_, bx)), cx)| {
            if *ax > (v_delta >> 1) {
                rho_mod
                    .reduce(*cx - rho_mod.reduce(backend.sub_z2k_const(*ax + rho - v_delta, *bx)))
            } else {
                rho_mod.reduce(*cx - rho_mod.reduce(backend.sub_z2k_const(*ax, *bx)))
            }
        })
        .collect();

    let res = backend.reveal_slice_z2k(&real_res, 0);
    let duration = start.elapsed();
    println!("DD online, Time elapsed: {} ns", duration.as_nanos());

    if backend.party_id() == 0 {
        let result: Option<Vec<u64>> = Some(
            res.iter()
                .map(|x| rho_mod.reduce(x.unwrap()) / v_delta)
                .collect(),
        );
        //println!("eda_elements:{:?}, result before div: {}, result: {}",open_eda_elements,result1,result);
        return result;
    } else {
        return None;
    }
    //modulus switch
}

pub fn generate_shared_bits_z2k<Backend, R>(
    backend: &mut Backend,
    rng: &mut R,
    len: u64,
) -> Vec<u64>
where
    Backend: MPCBackend,
    R: Rng,
{
    let t = backend.num_threshold();
    let id = backend.party_id();
    let b_vec: Vec<u64> = (0..len).map(|_| rng.gen_bool(0.5) as u64).collect();

    let b_vec_share: Vec<Vec<u64>> = (0..=t)
        .map(|i| {
            if id == i {
                backend.input_slice_with_prg_z2k(Some(&b_vec), len as usize, i)
            } else {
                backend.input_slice_with_prg_z2k(None, len as usize, i)
            }
        })
        .collect();

    b_vec_share
        .into_iter()
        .reduce(|b_x, b_y| {
            let temp1 = backend.add_z2k_slice(&b_x, &b_y);
            let temp2 = backend.mul_element_wise_z2k(&b_x, &b_y);
            let temp3 = backend.double_z2k_slice(&temp2);
            backend.sub_z2k_slice(&temp1, &temp3)
        })
        .unwrap()
}

pub fn generate_eda_elements<Backend, R>(
    backend: &mut Backend,
    rng: &mut R,
    len1: u64,
    len2: u64,
    triples_num: u64,
) -> Vec<(u64, u64)>
where
    Backend: MPCBackend,
    R: Rng,
{
    //println!("len1: {}, len2: {}", len1, len2);
    // let bits = generate_shared_bits_z2k(backend, rng, len2*triples_num);
    // let r_2:u64 = (0..len2).map(|i| bits[i as usize]*((2 as u64).pow(i as u32))).sum();
    // let r_1:u64 = (0..len1).map(|i| bits[(len2-1) as usize]*(2 as u64 ).pow((i+len2)as u32)).sum();
    // return vec![r_2, r_1+r_2];
    let bits = generate_shared_bits_z2k(backend, rng, len2 * triples_num);
    let results: Vec<(u64, u64)> = bits
        .chunks(len2 as usize)
        .map(|chunk| {
            let r_2 = chunk
                .iter()
                .enumerate()
                .map(|(i, bit)| bit * (2u64.pow(i as u32)))
                .sum::<u64>();

            let high_bit = chunk[(len2 - 1) as usize]; // 最高位
            let r_1 = (0..len1)
                .map(|i| high_bit * (2u64.pow((i + len2) as u32)))
                .sum::<u64>();

            (r_2, r_1 + r_2)
        })
        .collect();
    results
}
