use algebra::reduce::{Reduce, ReduceMul};
use algebra::Field;
use algebra::{modulus::PowOf2Modulus, reduce::ReduceInv};
use mpc::MPCBackend;
use rand::Rng;
use std::time::{Duration, Instant};

use crate::parameter::{Fp, DEFAULT_128_BITS_PARAMETERS};

pub fn distdec<Backend, R>(
    backend: &mut Backend,
    rng: &mut R,
    a: &[Vec<u64>],
    b: &[u64],
    shared_secret_key: &[Backend::Sharing],
) -> (Option<Vec<u64>>, (Duration, Duration))
where
    Backend: MPCBackend,
    R: Rng,
{
    let q: u64 = Fp::MODULUS_VALUE;
    let parameters = &DEFAULT_128_BITS_PARAMETERS;
    let p = parameters.lwe_plain_modulus();

    let len_p = (p as f64).log2().floor() as u64 + 1;
    let len_q = (q as f64).log2().floor() as u64 + 1;

    let rho: u64 = (2_u64).pow(len_q as u32);

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
    let offline_duration = start.elapsed();

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
        .reveal_slice_to_all_z2k(&res_vec, 64)
        .iter()
        .map(|x| v_delta_mod.reduce(*x))
        .collect();

    let real_res: Vec<u64> = res
        .iter()
        .zip(eda_elements.iter())
        .zip(u_prime_shares_vec.iter())
        .map(|((ax, (_, bx)), cx)| {
            if *ax > (v_delta >> 1) {
                rho_mod.reduce(
                    *cx - rho_mod.reduce(backend.sub_z2k_const(*ax + rho - v_delta, *bx, 64)),
                )
            } else {
                rho_mod.reduce(*cx - rho_mod.reduce(backend.sub_z2k_const(*ax, *bx, 64)))
            }
        })
        .collect();

    let res = backend.reveal_slice_z2k(&real_res, 0, 64);
    let online_duration = start.elapsed();

    if backend.party_id() == 0 {
        let result: Option<Vec<u64>> = Some(
            res.iter()
                .map(|x| rho_mod.reduce(x.unwrap()) / v_delta)
                .collect(),
        );
        //println!("eda_elements:{:?}, result before div: {}, result: {}",open_eda_elements,result1,result);
        (result, (online_duration, offline_duration))
    } else {
        (None, (online_duration, offline_duration))
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
            let temp1 = backend.add_z2k_slice(&b_x, &b_y, 64);
            let temp2 = backend.mul_element_wise_z2k(&b_x, &b_y, 64);
            let temp3 = backend.double_z2k_slice(&temp2, 64);
            backend.sub_z2k_slice(&temp1, &temp3, 64)
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
    //let bits = generate_shared_bits_z2k(backend, rng, len2 * triples_num, 64);
    let bits = generate_shared_bits_constant_round_z2k(
        backend,
        rng,
        len2 * triples_num,
        (len1 + len2) as u32,
    );
    let results: Vec<(u64, u64)> = bits
        .chunks(len2 as usize)
        .map(|chunk| {
            let r_2 = chunk
                .iter()
                .enumerate()
                .map(|(i, bit)| bit * (2u64.pow(i as u32)))
                .sum::<u64>();

            let high_bit = chunk[(len2 - 1) as usize];
            let r_1 = (0..len1)
                .map(|i| high_bit * (2u64.pow((i + len2) as u32)))
                .sum::<u64>();

            (r_2, r_1 + r_2)
        })
        .collect();
    results
}

pub fn generate_shared_bits_constant_round_z2k<Backend, R>(
    backend: &mut Backend,
    rng: &mut R,
    len: u64,
    k: u32,
) -> Vec<u64>
where
    Backend: MPCBackend,
    R: Rng,
{
    let my_power: u32 = k;
    let m = 1u64 << my_power;
    let m_mod = <PowOf2Modulus<u64>>::new(m);

    let r_vec: Vec<u64> = (0..len).map(|_| rng.next_u64()).collect();
    let shares = (0..=backend.num_threshold())
        .map(|i| {
            if backend.party_id() == i {
                backend.input_slice_with_prg_z2k(Some(&r_vec), len as usize, i)
            } else {
                backend.input_slice_with_prg_z2k(None, len as usize, i)
            }
        })
        .collect::<Vec<_>>();

    let a_vec = shares
        .into_iter()
        .reduce(|x, y| backend.add_z2k_slice(&x, &y, my_power))
        .unwrap();

    let u_vec = backend.mul_element_wise_z2k(&a_vec, &a_vec, my_power);

    let v_vec = backend.add_z2k_slice(&u_vec, &a_vec, my_power);
    let v_vec_open = backend.reveal_slice_to_all_z2k(&v_vec, my_power);

    let r_vec: Vec<Option<u64>> = v_vec_open
        .iter()
        .map(|x| solve(m_mod.reduce(*x), k))
        .collect();

    let r_vec: Vec<u64> = r_vec
        .iter()
        .map(|x| if let Some(x) = x { *x } else { 0u64 })
        .collect::<Vec<_>>();

    let d_vec: Vec<u64> = r_vec
        .iter()
        .map(|x| m_mod.reduce((1u64 << my_power) - 1 - 2 * m_mod.reduce(*x)))
        .collect::<Vec<_>>();

    // compute d^{-1}
    let d_reverse: Vec<u64> = if my_power < 64 {
        d_vec.iter().map(|&x| m.reduce_inv(x)).collect()
    } else {
        let m = 1u128 << my_power;
        d_vec
            .iter()
            .map(|&x| m.reduce_inv(x as u128) as u64)
            .collect()
    };

    // a-r
    let b_vec: Vec<u64> = a_vec
        .iter()
        .zip(r_vec.iter())
        .map(|(x, y)| backend.sub_z2k_const_a_sub_c(*x, *y, my_power))
        .collect();

    // (a-r)*(d^{-1})
    let b_vec: Vec<u64> = b_vec
        .iter()
        .zip(d_reverse.iter())
        .map(|(&x, &y)| m_mod.reduce_mul(x, y))
        .collect();

    b_vec
}

pub fn solve(v: u64, k: u32) -> Option<u64> {
    // if modulus 2^0 = 1
    if k == 0 {
        return Some(0);
    }
    // cpmpute mask (1 << k) - 1
    let mask: u64 = if k < 64 {
        (1u64 << k) - 1
    } else {
        u64::MAX // 2^64 - 1
    };
    //
    let v_mod = v & mask;
    //
    if v_mod & 1 == 1 {
        return None;
    }
    //
    let mut x = 0u128; // init soluation X ≡ 0 (mod 2)
    let v_mod_128 = v_mod as u128;
    //  mod 2^2, 2^3, ..., 2^k
    for i in 1..k {
        // 2^(i+1)
        let mod_val = 1u128 << (i + 1); // 2^(i+1)
        let mask_cur = mod_val - 1; // mask 2^(i+1) - 1
                                    // Compute f(X) = X^2 + X - v mod 2^(i+1)
        let lhs = (x * x + x) & mask_cur; // X^2 + X mod 2^(i+1)
        let rhs = v_mod_128 & mask_cur; // v mod  2^(i+1)
                                        //  Compute (lhs - rhs) mod 2^(i+1)
        let f_mod = (lhs + mod_val - rhs) & mask_cur;
        //  f_mod = (X^2 + X - v) mod 2^(i+1)，and satisfy f_mod can be divied by 2^i
        // Compute E = f_mod / 2^i ）
        let e_div_2i = f_mod >> i;
        // Based on Hensel lemma
        let t = e_div_2i & 1;

        x += t << i;
    }

    Some(x as u64)
}
