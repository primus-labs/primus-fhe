//! Independent integer quotients, dense native phases and adjacent-level bounds.
use dashu_int::IBig;
use primus_bgv::evaluation::BgvModulusSwitch;
use primus_bgv::{BgvCiphertext, BgvClient, BgvContext, BgvParameters};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;
use primus_shape::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 32;
const WIDE_Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];

fn context(p: u64, moduli: &[u64]) -> BgvContext {
    let parameters = BgvParameters::try_coefficients(
        PolyLength::new(N),
        BarrettModulus::new(p),
        &moduli
            .iter()
            .copied()
            .map(BarrettModulus::new)
            .collect::<Vec<_>>(),
        SecretKeyDistr::UniformTernary,
        ErrorDistribution::CenteredBinomial { eta: 1 },
    )
    .unwrap();
    BgvContext::try_with_levels(parameters, moduli.len()).unwrap()
}

fn product(moduli: &[u64]) -> IBig {
    moduli
        .iter()
        .fold(IBig::ONE, |product, &q| product * IBig::from(q))
}

fn canonical(value: &IBig, modulus: &IBig) -> IBig {
    let remainder = value % modulus;
    if remainder < IBig::ZERO {
        remainder + modulus
    } else {
        remainder
    }
}

fn centered(value: &IBig, modulus: &IBig) -> IBig {
    let residue = canonical(value, modulus);
    if residue > modulus >> 1 {
        residue - modulus
    } else {
        residue
    }
}

// Independent oracle: choose the nearest integer to x/q in the fixed class
// x modulo p. It does not use inverse-p residues, the RNS base or switch factors.
fn lattice_quotient(value: &IBig, divisor: &IBig, p: u64) -> IBig {
    let plain = IBig::from(p);
    assert_eq!(canonical(divisor, &plain), IBig::ONE);
    let message = canonical(value, &plain);
    let error = (value - &message) / &plain;
    let h = (divisor - IBig::ONE) / &plain;
    let shifted = error - h * &message + (divisor >> 1);
    let rounded = (&shifted - canonical(&shifted, divisor)) / divisor;
    message + plain * rounded
}

fn power(mut value: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = (u128::from(result) * u128::from(value) % u128::from(modulus)) as u64;
        }
        value = (u128::from(value) * u128::from(value) % u128::from(modulus)) as u64;
        exponent >>= 1;
    }
    result
}

// Incremental exact CRT uses only integer arithmetic and Fermat inverses of
// the fixed prime fixtures, independently of production RNSBase::compose_to.
fn compose(component: &[u64], moduli: &[u64]) -> Vec<IBig> {
    (0..N)
        .map(|degree| {
            let mut value = IBig::ZERO;
            let mut accumulated = IBig::ONE;
            for (limb, &q) in component.as_chunks::<N>().0.iter().zip(moduli) {
                let modulus = IBig::from(q);
                let delta =
                    u64::try_from(canonical(&(IBig::from(limb[degree]) - &value), &modulus))
                        .unwrap();
                let product_mod_q = u64::try_from(canonical(&accumulated, &modulus)).unwrap();
                let inverse = power(product_mod_q, q - 2, q);
                let digit = (u128::from(delta) * u128::from(inverse) % u128::from(q)) as u64;
                value += &accumulated * IBig::from(digit);
                accumulated *= modulus;
            }
            value
        })
        .collect()
}

fn transform(context: &BgvContext, level: usize, input: &mut [u64], inverse: bool) {
    for component in input.chunks_exact_mut(context.rns_poly_len(level)) {
        for (limb, table) in component
            .as_chunks_mut::<N>()
            .0
            .iter_mut()
            .zip(context.table().ntt_tables())
        {
            if inverse {
                table.inverse_transform_slice(limb);
            } else {
                table.transform_slice(limb);
            }
        }
    }
}

fn encode(context: &BgvContext, values: &[Vec<IBig>; 2]) -> BgvCiphertext<Vec<u64>> {
    let mut result = context.new_ciphertext(0);
    for (source, component) in values
        .iter()
        .zip(result.as_mut().chunks_exact_mut(context.rns_poly_len(0)))
    {
        for (limb, &q) in component
            .as_chunks_mut::<N>()
            .0
            .iter_mut()
            .zip(context.base_q(0).moduli_values())
        {
            for (out, value) in limb.iter_mut().zip(source) {
                *out = u64::try_from(canonical(value, &IBig::from(q))).unwrap();
            }
        }
    }
    transform(context, 0, result.as_mut(), false);
    result
}

fn coefficients(
    context: &BgvContext,
    level: usize,
    input: &BgvCiphertext<Vec<u64>>,
) -> [Vec<IBig>; 2] {
    let mut copy = input.as_ref().to_vec();
    transform(context, level, &mut copy, true);
    let (c0, c1) = copy.split_at(context.rns_poly_len(level));
    let moduli = context.base_q(level).moduli_values();
    [compose(c0, moduli), compose(c1, moduli)]
}

fn negacyclic(lhs: &[IBig], rhs: &[IBig]) -> Vec<IBig> {
    let mut result = vec![IBig::ZERO; N];
    for (i, a) in lhs.iter().enumerate() {
        for (j, b) in rhs.iter().enumerate() {
            let degree = i + j;
            if degree < N {
                result[degree] += a * b;
            } else {
                result[degree - N] -= a * b;
            }
        }
    }
    result
}

#[test]
fn exact_constrained_quotients_match_integer_oracle_and_compose_beyond_u128() {
    for (p, moduli) in [
        (2, [1_048_193, 1_047_041, 1_046_657]),
        (254, [1_007_873, 829_057, 585_217]),
        (193, WIDE_Q),
        (193, [WIDE_Q[2], WIDE_Q[1], WIDE_Q[0]]),
    ] {
        let context = context(p, &moduli);
        let total = product(&moduli);
        if p == 193 {
            assert!(total > (IBig::ONE << 128));
        }
        let drop = IBig::from(moduli[2]);
        let half = &total >> 1;
        let plain = IBig::from(p);
        let correction_half = &plain * (&drop >> 1);
        let boundaries = [
            IBig::ZERO,
            IBig::ONE,
            -IBig::ONE,
            &half - IBig::ONE,
            half.clone(),
            &half + IBig::ONE,
            -&half,
            -&half - IBig::ONE,
            &total - IBig::ONE,
            &total + IBig::ONE,
            (&drop >> 1) - IBig::ONE,
            &drop >> 1,
            (&drop >> 1) + IBig::ONE,
            &correction_half - &plain,
            correction_half.clone(),
            &correction_half + &plain,
            -&correction_half,
            -&correction_half - &plain,
        ];
        let original = std::array::from_fn(|component| {
            (0..N)
                .map(|index| boundaries[(index * 7 + component * 5) % boundaries.len()].clone())
                .collect::<Vec<_>>()
        });
        let mut expected = original.clone();
        let mut input = encode(&context, &original);
        let mut divisor = IBig::ONE;
        for level in 0..2 {
            let drop = IBig::from(moduli[2 - level]);
            divisor *= &drop;
            let target = product(context.base_q(level + 1).moduli_values());
            for component in &mut expected {
                for value in component {
                    *value = canonical(&lattice_quotient(value, &drop, p), &target);
                }
            }
            let mut output = context.new_ciphertext(level + 1);
            BgvModulusSwitch::new(&context, level).switch_to(&input, &mut output);
            let actual = coefficients(&context, level + 1, &output);
            assert_eq!(actual, expected);
            for (source, actual_component) in original.iter().zip(actual) {
                let direct: Vec<_> = source
                    .iter()
                    .map(|value| canonical(&lattice_quotient(value, &divisor, p), &target))
                    .collect();
                assert_eq!(actual_component, direct);
            }
            input = output;
        }
    }
    // Ordinary BFV rounding destroys this plaintext class.
    assert_eq!(
        lattice_quotient(&IBig::ONE, &IBig::from(103), 17),
        IBig::ONE
    );
    assert_eq!((1 + 103 / 2) / 103, 0);
}

#[test]
fn dense_same_secret_native_phase_and_constants_recover_across_all_levels() {
    for (p, moduli) in [
        (2, [1_048_193, 1_047_041, 1_046_657]),
        (254, [1_007_873, 829_057, 585_217]),
        (193, WIDE_Q),
    ] {
        let context = context(p, &moduli);
        let total = product(&moduli);
        let plain = IBig::from(p);
        let secret: Vec<i64> = (0..N)
            .map(|index| match index % 4 {
                0 => -1,
                1 => 0,
                _ => 1,
            })
            .collect();
        let integer_secret: Vec<_> = secret.iter().map(|&x| IBig::from(x)).collect();
        let coefficient_secret = GlweSecretKey::new(
            secret,
            context.parameters().size().glwe_size(),
            SecretKeyDistr::UniformTernary,
        );
        let mut client = BgvClient::try_from_secret_key(
            &context,
            DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_secret, context.table()),
        )
        .unwrap();
        for constant_only in [false, true] {
            let message: Vec<_> = (0..N)
                .map(|index| {
                    if constant_only && index != 0 {
                        IBig::ZERO
                    } else {
                        IBig::from(match index % 4 {
                            0 => p - 1,
                            1 => p / 2,
                            2 => 1,
                            _ => 0,
                        })
                    }
                })
                .collect();
            let expected: Vec<_> = message
                .iter()
                .map(|m| u64::try_from(m.clone()).unwrap())
                .collect();
            let mut phase: Vec<_> = message
                .iter()
                .enumerate()
                .map(|(i, m)| m + &plain * IBig::from((i % 7) as i64 - 3))
                .collect();
            let c1: Vec<_> = (0..N)
                .map(|i| &total / IBig::from(i + 2) + IBig::from(i * 65537 + 19))
                .collect();
            let c1s = negacyclic(&c1, &integer_secret);
            let c0: Vec<_> = phase
                .iter()
                .zip(c1s)
                .map(|(z, a)| canonical(&(z - a), &total))
                .collect();
            let mut input = encode(&context, &[c0, c1]);
            assert_eq!(client.decrypt_at_level(&input, 0).as_ref(), expected);
            for level in 0..2 {
                let source = coefficients(&context, level, &input);
                let drop = IBig::from(moduli[2 - level]);
                let target = product(context.base_q(level + 1).moduli_values());
                let remainders: [Vec<_>; 2] = std::array::from_fn(|component| {
                    source[component]
                        .iter()
                        .map(|x| {
                            let quotient = lattice_quotient(x, &drop, p);
                            let numerator = x - &drop * quotient;
                            assert_eq!(canonical(&numerator, &plain), IBig::ZERO);
                            let r = numerator / &plain;
                            assert!(r >= -(&drop >> 1) && r <= &drop >> 1);
                            r
                        })
                        .collect()
                });
                let rs = negacyclic(&remainders[1], &integer_secret);
                for (index, z) in phase.iter_mut().enumerate() {
                    let correction = &remainders[0][index] + &rs[index];
                    let numerator = &*z - &plain * correction;
                    assert_eq!(canonical(&numerator, &drop), IBig::ZERO);
                    *z = numerator / &drop;
                    assert_eq!(centered(z, &target), *z, "target phase must not wrap");
                    assert_eq!(canonical(z, &plain), message[index]);
                }
                let mut output = context.new_ciphertext(level + 1);
                BgvModulusSwitch::new(&context, level).switch_to(&input, &mut output);
                let actual = coefficients(&context, level + 1, &output);
                let as_secret = negacyclic(&actual[1], &integer_secret);
                for ((a, b), z) in actual[0].iter().zip(as_secret).zip(&phase) {
                    assert_eq!(centered(&(a + b), &target), *z);
                }
                assert_eq!(
                    client.decrypt_at_level(&output, level + 1).as_ref(),
                    expected
                );
                input = output;
            }
        }
    }
}

#[test]
fn unavailable_levels_and_malformed_storage_are_rejected_before_output_writes() {
    let context = context(193, &WIDE_Q);
    for level in [2, 3, usize::MAX] {
        assert!(catch_unwind(|| BgvModulusSwitch::new(&context, level)).is_err());
    }
    let valid = context.new_ciphertext(0);
    let mut switch = BgvModulusSwitch::new(&context, 0);
    for length in [0, 1, valid.as_ref().len() - 1, valid.as_ref().len() + 1] {
        let malformed = BgvCiphertext::from_raw(vec![0; length]);
        let mut output = context.new_ciphertext(1);
        output.as_mut().fill(73);
        let before = output.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                switch.switch_to(&malformed, &mut output);
            }))
            .is_err()
        );
        assert_eq!(output, before);
    }
    let target_len = context.new_ciphertext(1).as_ref().len();
    for length in [0, 1, target_len - 1, target_len + 1] {
        let mut output = BgvCiphertext::from_raw(vec![73; length]);
        let before = output.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                switch.switch_to(&valid, &mut output);
            }))
            .is_err()
        );
        assert_eq!(output, before);
    }
    let mut output = context.new_ciphertext(1);
    switch.switch_to(&valid, &mut output);
    assert!(output.as_ref().iter().all(|&x| x == 0));
}
