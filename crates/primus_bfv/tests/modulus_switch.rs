//! Exact component rounding and same-secret phase recovery across prefix levels.

use dashu_int::UBig;
use primus_bfv::{BfvCiphertext, BfvContext, BfvModulusSwitch, BfvParameters, BfvSecretKeyContext};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 32;
const SMALL_Q: [u64; 3] = [65_537, 114_689, 147_457];

fn context(moduli: &[u64]) -> BfvContext {
    let parameters = BfvParameters::try_with_error_distribution(
        PolyLength::new(N),
        BarrettModulus::new(17),
        BarrettModulus::new(257),
        &moduli
            .iter()
            .copied()
            .map(BarrettModulus::new)
            .collect::<Vec<_>>(),
        SecretKeyDistr::UniformBinary,
        ErrorDistribution::CenteredBinomial { eta: 1 },
    )
    .unwrap();
    BfvContext::try_with_levels(parameters, moduli.len()).unwrap()
}

fn transform(context: &BfvContext, level: usize, ciphertext: &mut [u64], inverse: bool) {
    for component in ciphertext.chunks_exact_mut(context.rns_poly_len(level)) {
        for (limb, table) in component
            .as_chunks_mut::<N>()
            .0
            .iter_mut()
            .zip(context.table().iter())
        {
            if inverse {
                table.inverse_transform_slice(limb);
            } else {
                table.transform_slice(limb);
            }
        }
    }
}

fn encode_u128(context: &BfvContext, values: &[u128]) -> BfvCiphertext<Vec<u64>> {
    assert_eq!(values.len(), 2 * N);
    let mut ciphertext = context.new_ciphertext(0);
    for (source, component) in values.as_chunks::<N>().0.iter().zip(
        ciphertext
            .as_mut()
            .chunks_exact_mut(context.rns_poly_len(0)),
    ) {
        for (&q, limb) in context
            .codec(0)
            .moduli_values()
            .iter()
            .zip(component.as_chunks_mut::<N>().0.iter_mut())
        {
            for (&value, out) in source.iter().zip(limb) {
                *out = (value % u128::from(q)) as u64;
            }
        }
    }
    transform(context, 0, ciphertext.as_mut(), false);
    ciphertext
}

fn power(mut value: u128, mut exponent: u64, modulus: u128) -> u128 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * value % modulus;
        }
        value = value * value % modulus;
        exponent >>= 1;
    }
    result
}

// Independent incremental integer CRT: neither RNSBase nor the switching
// implementation's inverse factors/centered remainder are used here.
fn compose_u128(component: &[u64], moduli: &[u64]) -> Vec<u128> {
    (0..N)
        .map(|degree| {
            let mut value = 0;
            let mut product = 1;
            for (limb, &q) in component.as_chunks::<N>().0.iter().zip(moduli) {
                let q128 = u128::from(q);
                let difference = (u128::from(limb[degree]) + q128 - value % q128) % q128;
                let inverse = power(product % q128, q - 2, q128);
                value += product * (difference * inverse % q128);
                product *= q128;
            }
            value
        })
        .collect()
}

fn integer_components(
    context: &BfvContext,
    level: usize,
    ciphertext: &BfvCiphertext<Vec<u64>>,
) -> [Vec<u128>; 2] {
    let mut coefficients = ciphertext.as_ref().to_vec();
    transform(context, level, &mut coefficients, true);
    let (c0, c1) = coefficients.split_at(context.rns_poly_len(level));
    let moduli = context.codec(level).moduli_values();
    [compose_u128(c0, moduli), compose_u128(c1, moduli)]
}

#[test]
fn adjacent_drops_match_integer_division_and_odd_rounding_composes() {
    for moduli in [SMALL_Q, [SMALL_Q[2], SMALL_Q[1], SMALL_Q[0]]] {
        let context = context(&moduli);
        let q: u128 = moduli.iter().map(|&q| u128::from(q)).product();
        let p = u128::from(moduli[2]);
        let boundary_values = [
            0,
            1,
            p / 2 - 1,
            p / 2,
            p / 2 + 1,
            p - 1,
            p,
            p + p / 2 - 1,
            p + p / 2,
            p + p / 2 + 1,
            q / 2 - 1,
            q / 2,
            q / 2 + 1,
            q - p - 1,
            q - p,
            q - 1,
        ];
        let original: Vec<_> = (0..2 * N)
            .map(|index| boundary_values[(index * 7 + index / N) % boundary_values.len()])
            .collect();
        let mut expected = original.clone();
        let mut input = encode_u128(&context, &original);
        for level in 0..2 {
            let p = u128::from(*context.codec(level).moduli_values().last().unwrap());
            let target_q: u128 = context
                .codec(level + 1)
                .moduli_values()
                .iter()
                .map(|&q| u128::from(q))
                .product();
            for value in &mut expected {
                *value = (*value + p / 2) / p % target_q;
            }
            let mut output = context.new_ciphertext(level + 1);
            BfvModulusSwitch::new(&context, level).switch_to(&input, &mut output);
            let actual = integer_components(&context, level + 1, &output);
            assert_eq!(actual.concat(), expected);
            input = output;
        }
        let divisor = u128::from(moduli[1]) * u128::from(moduli[2]);
        let direct: Vec<_> = original
            .iter()
            .map(|&value| (value + divisor / 2) / divisor % u128::from(moduli[0]))
            .collect();
        assert_eq!(expected, direct);
    }
}

#[test]
fn four_prime_product_beyond_u128_matches_independent_big_integer_division() {
    let moduli = [
        1_125_899_906_826_241,
        1_125_899_906_629_633,
        1_125_899_906_031_617,
        1_125_899_904_679_937,
    ];
    let context = context(&moduli);
    let product = moduli
        .iter()
        .fold(UBig::ONE, |product, &q| product * UBig::from(q));
    assert!(product > UBig::from(u128::MAX));
    let half = &product >> 1;
    let p = UBig::from(moduli[3]);
    let boundary_values = [
        UBig::ZERO,
        UBig::ONE,
        (&p >> 1) - UBig::ONE,
        &p >> 1,
        (&p >> 1) + UBig::ONE,
        &p - UBig::ONE,
        &half - UBig::ONE,
        half.clone(),
        &half + UBig::ONE,
        &product - UBig::ONE,
    ];
    let mut expected: Vec<_> = (0..2 * N)
        .map(|index| boundary_values[(index * 7) % boundary_values.len()].clone())
        .collect();
    let original = expected.clone();
    let mut input = context.new_ciphertext(0);
    for (source, component) in expected
        .as_chunks::<N>()
        .0
        .iter()
        .zip(input.as_mut().chunks_exact_mut(context.rns_poly_len(0)))
    {
        for (&q, limb) in moduli
            .iter()
            .zip(component.as_chunks_mut::<N>().0.iter_mut())
        {
            for (value, out) in source.iter().zip(limb) {
                *out = u64::try_from(value % UBig::from(q)).unwrap();
            }
        }
    }
    transform(&context, 0, input.as_mut(), false);
    let mut divisor = UBig::ONE;
    for level in 0..3 {
        let p = UBig::from(moduli[3 - level]);
        divisor *= &p;
        let target_q = &product / &divisor;
        for value in &mut expected {
            *value = (&*value + (&p >> 1)) / &p % &target_q;
        }
        let mut output = context.new_ciphertext(level + 1);
        BfvModulusSwitch::new(&context, level).switch_to(&input, &mut output);
        let mut coefficients = output.as_ref().to_vec();
        transform(&context, level + 1, &mut coefficients, true);
        for (expected_component, actual_component) in expected
            .as_chunks::<N>()
            .0
            .iter()
            .zip(coefficients.chunks_exact(context.rns_poly_len(level + 1)))
        {
            for (&q, limb) in context
                .codec(level + 1)
                .moduli_values()
                .iter()
                .zip(actual_component.as_chunks::<N>().0.iter())
            {
                for (value, &actual) in expected_component.iter().zip(limb) {
                    assert_eq!(actual, u64::try_from(value % UBig::from(q)).unwrap());
                }
            }
        }
        for (value, original) in expected.iter().zip(&original) {
            assert_eq!(
                value,
                &((original + (&divisor >> 1)) / &divisor % &target_q)
            );
        }
        input = output;
    }
}

fn phase(c0: &[u128], c1: &[u128], secret: &[i64]) -> Vec<i128> {
    let mut output: Vec<_> = c0.iter().map(|&value| value as i128).collect();
    for (i, &value) in c1.iter().enumerate() {
        for (j, &secret) in secret.iter().enumerate() {
            output[(i + j) % N] +=
                value as i128 * i128::from(secret) * if i + j < N { 1 } else { -1 };
        }
    }
    output
}

#[test]
fn same_actual_secret_recovers_after_every_drop_and_matches_rounding_phase() {
    let context = context(&SMALL_Q);
    let parameters = context.parameters();
    let secret: Vec<_> = (0..N).map(|index| i64::from(index % 3 == 0)).collect();
    let coefficient_key = GlweSecretKey::new(
        secret.clone(),
        parameters.size().glwe_size(),
        SecretKeyDistr::UniformBinary,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, context.table());
    let encryptor = BfvSecretKeyContext::try_new(&key, &context).unwrap();
    let message = Polynomial(
        (0..N)
            .map(|index| (index * 7 % 17) as u64)
            .collect::<Vec<_>>(),
    );
    for centered in [false, true] {
        let mut input = context.new_ciphertext(0);
        let mut rng = StdRng::seed_from_u64(0x4246_5606);
        if centered {
            encryptor.encrypt_centered_to(&message, &mut input, &mut rng);
        } else {
            encryptor.encrypt_to(&message, &mut input, &mut rng);
        }
        for level in 0..3 {
            let old = integer_components(&context, level, &input);
            let old_phase = phase(&old[0], &old[1], &secret);
            let q: u128 = context
                .codec(level)
                .moduli_values()
                .iter()
                .map(|&q| u128::from(q))
                .product();
            for (&phase, &message) in old_phase.iter().zip(message.as_ref()) {
                let canonical = phase.rem_euclid(q as i128) as u128;
                assert_eq!(((canonical * 17 + q / 2) / q % 17) as u64, message);
            }
            if level == 2 {
                break;
            }
            let p = u128::from(*context.codec(level).moduli_values().last().unwrap());
            let mut output = context.new_ciphertext(level + 1);
            BfvModulusSwitch::new(&context, level).switch_to(&input, &mut output);
            let new = integer_components(&context, level + 1, &output);
            let new_phase = phase(&new[0], &new[1], &secret);
            let deltas: [Vec<i128>; 2] = std::array::from_fn(|component| {
                old[component]
                    .iter()
                    .map(|&value| (((value + p / 2) / p) * p) as i128 - value as i128)
                    .collect()
            });
            for delta in deltas.iter().flatten() {
                assert!(delta.unsigned_abs() <= p / 2);
            }
            // p*phase(out)-phase(in) = delta0+delta1*s mod Q.
            let mut delta_phase = deltas[0].clone();
            for (i, &delta) in deltas[1].iter().enumerate() {
                for (j, &secret) in secret.iter().enumerate() {
                    delta_phase[(i + j) % N] +=
                        delta * i128::from(secret) * if i + j < N { 1 } else { -1 };
                }
            }
            for ((new, old), delta) in new_phase.iter().zip(&old_phase).zip(&delta_phase) {
                assert_eq!((new * p as i128 - old - delta).rem_euclid(q as i128), 0);
            }
            input = output;
        }
    }
}

#[test]
fn invalid_levels_and_complete_shapes_fail_before_output_writes() {
    let context = context(&SMALL_Q);
    for source_level in [2, 3, usize::MAX] {
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                BfvModulusSwitch::new(&context, source_level)
            }))
            .is_err()
        );
    }
    let mut switch = BfvModulusSwitch::new(&context, 0);
    let input = context.new_ciphertext(0);
    for length in [
        0,
        2 * context.rns_poly_len(0) - 1,
        2 * context.rns_poly_len(0) + 1,
    ] {
        let malformed = BfvCiphertext::new(vec![0; length]);
        let mut output = context.new_ciphertext(1);
        output.as_mut().fill(99);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                switch.switch_to(&malformed, &mut output)
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 99));
    }
    for length in [
        0,
        2 * context.rns_poly_len(1) - 1,
        2 * context.rns_poly_len(1) + 1,
    ] {
        let mut output = BfvCiphertext::new(vec![99; length]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                switch.switch_to(&input, &mut output)
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 99));
    }
    // Reuse after all rejected operations still overwrites both components.
    let mut output = context.new_ciphertext(1);
    switch.switch_to(&input, &mut output);
    assert!(output.as_ref().iter().all(|&value| value == 0));
}

#[test]
fn borrowed_parts_check_the_actual_table_and_exact_unique_prefix() {
    let context = context(&SMALL_Q);
    let source = context.codec(0).base_q().moduli();
    let target = context.codec(1).base_q().moduli();
    let values: Vec<_> = (0..2 * N)
        .map(|i| i as u128 * u128::from(SMALL_Q[2]) + u128::from(SMALL_Q[2] / 2) + (i % 2) as u128)
        .collect();
    let input = encode_u128(&context, &values);
    let mut output = context.new_ciphertext(1);
    BfvModulusSwitch::try_from_parts(context.table(), source, target)
        .unwrap()
        .switch_to(&input, &mut output);
    let expected: Vec<_> = values
        .iter()
        .map(|&x| (x + u128::from(SMALL_Q[2] / 2)) / u128::from(SMALL_Q[2]))
        .collect();
    let actual = integer_components(&context, 1, &output);
    assert_eq!(actual[0], expected[..N]);
    assert_eq!(actual[1], expected[N..]);

    assert!(BfvModulusSwitch::try_from_parts(context.table(), source, &[]).is_err());
    assert!(BfvModulusSwitch::try_from_parts(context.table(), source, &source[..1]).is_err());
    let reordered = [target[1], target[0]];
    assert!(BfvModulusSwitch::try_from_parts(context.table(), source, &reordered).is_err());
    let repeated = [source[0], source[0]];
    let repeated_table = primus_ntt::U64DcrtTable::new(PolyLength::new(N), &repeated).unwrap();
    assert!(BfvModulusSwitch::try_from_parts(&repeated_table, &repeated, &repeated[..1]).is_err());
}
