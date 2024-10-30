use algebra::{derive::*, FieldUniformSampler};
use num_traits::{One, Zero};
use pcs::utils::code::{ExpanderCode, ExpanderCodeSpec, LinearCode};
use rand::Rng;

#[derive(Field)]
#[modulus = 32]
pub struct FF32(u64);

/// test whether the code is linear
/// the test compares Enc(k1 * m1 + k2 * m2) and k1 * Enc(m1) + k2 * Enc(m2)
#[test]
fn linearity_check() {
    let mut rng = rand::thread_rng();
    let field_distr = FieldUniformSampler::new();

    let spec = ExpanderCodeSpec::new(0.1195, 0.0284, 1.420, 31, 30);
    let brakedown_code: ExpanderCode<FF32> = ExpanderCode::new(spec, 5000, &mut rng);

    let message_len = brakedown_code.message_len;
    let codeword_len = brakedown_code.codeword_len;

    let check_times = 100;
    for _ in 0..check_times {
        let k_0 = rng.sample(field_distr);
        let k_1 = rng.sample(field_distr);

        let mut codeword = vec![FF32::zero(); codeword_len];
        codeword[..message_len]
            .iter_mut()
            .for_each(|x| *x = rng.sample(field_distr));

        let mut codeword_add = vec![FF32::zero(); codeword_len];
        codeword_add[..message_len]
            .iter_mut()
            .for_each(|x| *x = rng.sample(field_distr));

        let mut codeword_sum: Vec<FF32> = codeword
            .clone()
            .into_iter()
            .zip(codeword_add.clone())
            .map(|(x_0, x_1)| k_0 * x_0 + k_1 * x_1)
            .collect();
        brakedown_code.encode(&mut codeword_sum);

        brakedown_code.encode(&mut codeword);
        brakedown_code.encode(&mut codeword_add);
        let codeword_sum_expected: Vec<FF32> = codeword
            .clone()
            .into_iter()
            .zip(codeword_add.clone())
            .map(|(x_0, x_1)| k_0 * x_0 + k_1 * x_1)
            .collect();

        let num_notequal: usize = codeword_sum_expected
            .iter()
            .zip(codeword_sum.iter())
            .map(|(x_0, x_1)| (x_0 != x_1) as usize)
            .sum();
        assert!(num_notequal == 0);
    }
}

/// test the real code distance is larger or equal to the ideal minimum code distance
/// two random codewords have large distance to each other with high probability, making it inefficient to find two closed codewords
/// the test iteratively adds 1 to the first element of the message and compare its codeword to the original codeword
#[test]
fn code_distance_test() {
    let mut rng = rand::thread_rng();
    let field_distr = FieldUniformSampler::new();

    let spec = ExpanderCodeSpec::new(0.1195, 0.0284, 1.420, 31, 10);
    let brakedown_code: ExpanderCode<FF32> = ExpanderCode::new(spec, 5000, &mut rng);

    let message_len = brakedown_code.message_len;
    let codeword_len = brakedown_code.codeword_len;

    let mut target_0 = vec![FF32::zero(); codeword_len];

    target_0[..message_len]
        .iter_mut()
        .for_each(|x| *x = rng.sample(field_distr));

    let mut target_1 = target_0.clone();

    let check_times = 31;
    for _ in 0..check_times {
        target_1[0] += FF32::one();
        brakedown_code.encode(&mut target_0);
        brakedown_code.encode(&mut target_1);
        let num_real: usize = target_0
            .iter()
            .zip(target_1.iter())
            .map(|(x_0, x_1)| (x_0 != x_1) as usize)
            .sum();
        let num_expected = (brakedown_code.distance() * codeword_len as f64) as usize;
        if num_real < num_expected {
            println!("num real {:?} num expected {:?}", num_real, num_expected);
        };
        assert!(num_real >= num_expected);
    }
}
