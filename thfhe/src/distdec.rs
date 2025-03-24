use algebra::Field;
use std::time::Instant;
use std::u64;

use mpc::MPCBackend;
use rand::Rng;

use crate::parameter::{Fp, DEFAULT_128_BITS_PARAMETERS};

pub fn distdec<Backend, R>(
    backend: &mut Backend,
    rng: &mut R,
    a: &[u64],
    b: u64,
    shared_secret_key: &[Backend::Sharing],
) -> Option<u64>
where
    Backend: MPCBackend,
    R: Rng,
{
    //println!("my_id:{},b: {:?} ",backend.party_id(),b);
    let q: u64 = Fp::MODULUS_VALUE;
    let parameters = &DEFAULT_128_BITS_PARAMETERS;
    let p = parameters.lwe_plain_modulus();

    //let delta = (q as f64 / p as f64).round() as u64;
    let len_p = (p as f64).log2().floor() as u64 + 1;
    let len_q = (q as f64).log2().floor() as u64 + 1;
    // println!("len_p : {}, len_q : {} ", len_p, len_q);

    let rho: u64 = (2 as u64).pow(len_q as u32);
    // println!("rho: {}, len_rho : {} ", rho, len_q+1);
    // println!("rho/q : {} ", rho as f64/q as f64);

    let v_delta: u64 = rho / p;
    // println!("v_delta: {}",v_delta);

    let start = Instant::now();
    let eda_elements = generate_eda_elements(backend, rng, len_p, (v_delta as f64).log2() as u64);
    let duration = start.elapsed();
    println!(
        "DD offline, prepare eda elements, Time elapsed: {} ns",
        duration.as_nanos()
    );

    let start = Instant::now();

    //  convert shamir to additive over F_q
    let additive_shares = backend.shamir_secrets_to_additive_secrets(shared_secret_key);
    // println!("my_id:{},additive_shares : {:?} ",backend.party_id(),additive_shares[0]);

    //as mod q
    let a_mul_s_sum = backend.inner_product_additive_const_p(a, &additive_shares);
    // println!("len a: {},len s: {}",a.len(),additive_shares.len());
    // println!("my_id: {},a_mul_s_sum: {:?} ",backend.party_id(),a_mul_s_sum);

    // m_add_e = b-as mod q
    let m_add_e_shares: u64 = backend.sub_additive_const_p(b, a_mul_s_sum);
    // println!("my_id:{},m_add_e_shares: {:?} ",backend.party_id(),m_add_e_shares);
    // println!("my_id:{},b: {:?} ",backend.party_id(),b);

    //modulus switch
    let u_prime_shares = ((rho as f64) * (m_add_e_shares as f64 / q as f64)).round() as u64;
    // println!("my_id:{},u_prime_shares: {}",backend.party_id(),u_prime_shares);

    // exact e shares over vdelta
    let e_prime_shares_vdelta = u_prime_shares % v_delta;
    // println!("my_id:{},e_prime_shares_vdelta: {}",backend.party_id(),e_prime_shares_vdelta);

    //create (r_shares over rho and r_shares over v_delta)

    // let open_eda_elements = backend.reveal_slice_to_all_z2k(&eda_elements);
    // println!("Open_eda_elements:{:?}, {} mod {} result {}",open_eda_elements, open_eda_elements[1], v_delta, open_eda_elements[1]%( (2 as u64).pow((len_q - len_p) as u32)) );

    // compute e_prime_shares + r_shares over v_delta and reveal
    let res = backend.reveal_slice_to_all_z2k(&vec![e_prime_shares_vdelta + eda_elements[0]])[0]
        % v_delta;
    // println!("e'+r: {}", res);

    let real_res = if res > v_delta / 2 {
        res + rho - v_delta
    } else {
        res
    };

    let e_prime_shares_rho = backend.sub_z2k_const(real_res, eda_elements[1]) % rho;
    //println!("e'+r - <r>: {}", e_prime_shares_rho);

    let res = backend.reveal_slice_z2k(&vec![(u_prime_shares - e_prime_shares_rho) % rho], 0);

    let duration = start.elapsed();
    println!("DD online, Time elapsed: {} ns", duration.as_nanos());

    if backend.party_id() == 0 {
        let result1 = res[0].unwrap() % rho;
        let result = result1 / v_delta;
        //println!("eda_elements:{:?}, result before div: {}, result: {}",open_eda_elements,result1,result);
        Some(result)
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
                backend.input_slice_z2k(Some(&b_vec), len as usize, i)
            } else {
                backend.input_slice_z2k(None, len as usize, i)
            }
        })
        .collect();

    backend.init_z2k_triples_from_files();

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
) -> Vec<u64>
where
    Backend: MPCBackend,
    R: Rng,
{
    //println!("len1: {}, len2: {}", len1, len2);
    let bits = generate_shared_bits_z2k(backend, rng, len2);
    let r_2: u64 = (0..len2)
        .map(|i| bits[i as usize] * ((2 as u64).pow(i as u32)))
        .sum();
    let r_1: u64 = (0..len1)
        .map(|i| bits[(len2 - 1) as usize] * (2 as u64).pow((i + len2) as u32))
        .sum();
    return vec![r_2, r_1 + r_2];
}
