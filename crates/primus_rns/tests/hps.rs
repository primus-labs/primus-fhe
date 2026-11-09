use dashu_int::IBig;
use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_modulus::BarrettModulus;
use primus_rns::{HpsRns, RNSBase, RnsError};

type Base = RNSBase<u64, BarrettModulus<u64>>;

fn base(moduli: &[u64]) -> Base {
    Base::new(
        &moduli
            .iter()
            .copied()
            .map(BarrettModulus::new)
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn residues(values: &[i128], moduli: &[u64]) -> Vec<u64> {
    moduli
        .iter()
        .flat_map(|&modulus| {
            values
                .iter()
                .map(move |&value| value.rem_euclid(modulus as i128) as u64)
        })
        .collect()
}

fn inverse(value: i128, modulus: i128) -> i128 {
    // Extended Euclid, independent of the production modular precomputation.
    let (mut r0, mut r1, mut s0, mut s1) = (modulus, value.rem_euclid(modulus), 0, 1);
    while r1 != 0 {
        let quotient = r0 / r1;
        (r0, r1) = (r1, r0 - quotient * r1);
        (s0, s1) = (s1, s0 - quotient * s1);
    }
    assert_eq!(r0, 1);
    s0.rem_euclid(modulus)
}

#[test]
fn hps_centered_expansion_and_prescaling_match_integer_residual_oracle() {
    let mut observed_wrap = false;
    for (q_moduli, p_moduli) in [
        (&[17][..], &[19, 23][..]),
        (&[17, 19][..], &[23][..]),
        (&[17, 19][..], &[23, 29][..]),
    ] {
        let q = q_moduli.iter().map(|&q| q as i128).product::<i128>();
        let p = p_moduli.iter().map(|&p| p as i128).product::<i128>();
        let values: Vec<_> = (-(q / 2)..=q / 2).collect();
        let input = residues(&values, q_moduli);
        let hps = HpsRns::try_new(&base(q_moduli), &base(p_moduli), 3).unwrap();
        let mut workspace = hps.workspace(values.len());
        let mut output = vec![0; p_moduli.len() * values.len()];
        hps.expand_q_to_p(&input, &mut output, values.len(), &mut workspace);
        assert_eq!(output, residues(&values, p_moduli));

        let scaled: Vec<_> = values
            .iter()
            .map(|&x| {
                let numerator: i128 = q_moduli
                    .iter()
                    .map(|&qi| {
                        let qi = qi as i128;
                        let qi_hat = q / qi;
                        let d = (-p * x * inverse(qi_hat, qi)).rem_euclid(qi);
                        d * qi_hat
                    })
                    .sum();
                assert!(numerator >= 0 && numerator < q_moduli.len() as i128 * q);
                let sum = p * x + numerator;
                assert_eq!(sum % q, 0);
                sum / q
            })
            .collect();
        observed_wrap |= scaled.iter().any(|&y| y > p / 2);
        hps.scale_q_to_p(&input, &mut output, values.len(), &mut workspace);
        assert_eq!(output, residues(&scaled, p_moduli));
        // Reconstructing on the P side selects its centered representative,
        // including the top-of-Q wrap caused by the one-sided residual.
        let centered_scaled: Vec<_> = scaled
            .iter()
            .map(|&y| (y + p / 2).rem_euclid(p) - p / 2)
            .collect();
        let mut back_q = vec![0; input.len()];
        hps.expand_p_to_q(&output, &mut back_q, values.len(), &mut workspace);
        assert_eq!(back_q, residues(&centered_scaled, q_moduli));
    }
    assert!(
        observed_wrap,
        "oracle cases must include kappa=1 centered-P wrap"
    );
}

#[test]
fn hps_scale_and_round_matches_signed_integer_oracle_at_every_p_remainder() {
    let (q_moduli, p_moduli) = ([17, 19], [23, 29]);
    let (q, p) = (323_i128, 667_i128);
    let values: Vec<_> = [-(q / 2), -1, 0, 1, q / 2]
        .iter()
        .flat_map(|&quotient| (-(p / 2)..=p / 2).map(move |remainder| quotient * p + remainder))
        .collect();
    let input_q = residues(&values, &q_moduli);
    let input_p = residues(&values, &p_moduli);
    for t in [1, 2, 17, 67, u64::MAX] {
        let hps = HpsRns::try_new(&base(&q_moduli), &base(&p_moduli), t).unwrap();
        let mut workspace = hps.workspace(values.len());
        let mut output = vec![0; input_q.len()];
        hps.scale_and_round(
            &input_q,
            &input_p,
            &mut output,
            values.len(),
            &mut workspace,
        );
        let expected: Vec<_> = values
            .iter()
            .map(|&value| {
                let numerator = value * t as i128;
                if numerator >= 0 {
                    (numerator + p / 2) / p
                } else {
                    -((-numerator + p / 2) / p)
                }
            })
            .collect();
        assert_eq!(output, residues(&expected, &q_moduli));
    }
}

fn big_product(moduli: &[u64]) -> IBig {
    moduli
        .iter()
        .fold(IBig::ONE, |product, &modulus| product * modulus)
}

fn big_residue(value: &IBig, modulus: u64) -> u64 {
    let m = IBig::from(modulus);
    u64::try_from(((value % &m) + &m) % &m).unwrap()
}

fn big_residues(values: &[IBig], moduli: &[u64]) -> Vec<u64> {
    moduli
        .iter()
        .flat_map(|&modulus| values.iter().map(move |value| big_residue(value, modulus)))
        .collect()
}

fn big_nearest(numerator: &IBig, denominator: &IBig) -> IBig {
    if numerator < &IBig::ZERO {
        -((-numerator + denominator / 2_u8) / denominator)
    } else {
        (numerator + denominator / 2_u8) / denominator
    }
}

const WIDE_Q: [u64; 3] = [
    1_152_921_504_606_830_593,
    1_152_921_504_606_748_673,
    1_152_921_504_606_683_137,
];
const WIDE_P: [u64; 3] = [
    1_152_921_504_606_601_217,
    1_152_921_504_606_584_833,
    1_152_921_504_606_502_913,
];

#[test]
fn exact_expansion_handles_wide_centered_half_boundaries() {
    let target = [65_537, 114_689];
    let q = big_product(&WIDE_Q);
    assert!(q > IBig::from(u128::MAX));
    let half = &q / 2_u8;
    let mut values: Vec<_> = [-2_i8, -1, 0, 1, 2]
        .iter()
        .map(|&step| &half + IBig::from(step))
        .chain([IBig::ZERO, IBig::ONE, &q - 1_u8])
        .collect();
    let mut state = 0x64e7_a912_30b5_f68d_u64;
    for _ in 0..24 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let high = IBig::from(state) * IBig::from(u128::MAX);
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        values.push((high + state) % &q);
    }
    let centered: Vec<_> = values
        .iter()
        .map(|value| {
            if value > &half {
                value - &q
            } else {
                value.clone()
            }
        })
        .collect();
    let input = big_residues(&values, &WIDE_Q);
    let expected = big_residues(&centered, &target);
    let hps = HpsRns::try_new(&base(&WIDE_Q), &base(&target), 65_537).unwrap();
    let mut workspace = hps.workspace(values.len());
    let mut output = vec![0; expected.len()];
    hps.expand_q_to_p(&input, &mut output, values.len(), &mut workspace);
    assert_eq!(output, expected);
    let reverse = HpsRns::try_new(&base(&target), &base(&WIDE_Q), 65_537).unwrap();
    let mut reverse_workspace = reverse.workspace(values.len());
    reverse.expand_p_to_q(&input, &mut output, values.len(), &mut reverse_workspace);
    assert_eq!(output, expected);
}

#[test]
fn wide_prescaling_matches_exact_integer_quotient_and_residual() {
    let q = big_product(&WIDE_Q);
    let p = big_product(&WIDE_P);
    let half = &q / 2_u8;
    let values: Vec<_> = [-2_i8, -1, 0, 1, 2]
        .iter()
        .map(|&step| &half + IBig::from(step))
        .chain([
            IBig::ZERO,
            IBig::ONE,
            IBig::from((1_u64 << 53) + 1),
            &q - 1_u8,
        ])
        .collect();
    let input = big_residues(&values, &WIDE_Q);
    let mut observed_nonzero_residual = false;
    let expected: Vec<_> = values
        .iter()
        .map(|value| {
            // Reconstruct the exact integer numerator r=sum d_i*(Q/q_i),
            // then compute (P*x+r)/Q by independent arbitrary-precision division.
            let numerator = WIDE_Q.iter().fold(IBig::ZERO, |sum, &qi| {
                let q_hat = &q / qi;
                let inverse_hat = inverse(big_residue(&q_hat, qi) as i128, qi as i128);
                let d = big_residue(&(-&p * value * IBig::from(inverse_hat)), qi);
                sum + q_hat * d
            });
            assert!(numerator >= IBig::ZERO && numerator < &q * WIDE_Q.len());
            observed_nonzero_residual |= numerator != IBig::ZERO;
            let combined = &p * value + numerator;
            assert_eq!(&combined % &q, IBig::ZERO);
            combined / &q
        })
        .collect();
    assert!(observed_nonzero_residual);
    let hps = HpsRns::try_new(&base(&WIDE_Q), &base(&WIDE_P), 65_537).unwrap();
    let mut workspace = hps.workspace(values.len());
    let mut output = vec![0; WIDE_P.len() * values.len()];
    hps.scale_q_to_p(&input, &mut output, values.len(), &mut workspace);
    assert_eq!(output, big_residues(&expected, &WIDE_P));
}

#[test]
fn hps_rejects_invalid_parameters_and_shapes_before_writes() {
    assert!(matches!(
        HpsRns::try_new(&base(&[17]), &base(&[17]), 3),
        Err(RnsError::NonCoprimeModuli)
    ));
    assert!(matches!(
        HpsRns::try_new(&base(&[17]), &base(&[19]), 0),
        Err(RnsError::ZeroScale)
    ));
    assert!(matches!(
        HpsRns::try_new(&base(&[16]), &base(&[19]), 3),
        Err(RnsError::UnsupportedHpsModulus { .. })
    ));
    let hps = HpsRns::try_new(&base(&[17, 19]), &base(&[23]), 3).unwrap();
    for operation in 0..4 {
        let mut output = vec![u64::MAX; if operation < 2 { 3 } else { 8 }];
        let mut workspace = hps.workspace(4);
        let input_q = vec![0; 8];
        let input_p = vec![0; 4];
        assert!(
            catch_unwind(AssertUnwindSafe(|| match operation {
                0 => hps.expand_q_to_p(&input_q, &mut output, 4, &mut workspace),
                1 => hps.scale_q_to_p(&input_q, &mut output, 4, &mut workspace),
                2 => hps.expand_p_to_q(&input_p[..3], &mut output, 4, &mut workspace),
                _ => hps.scale_and_round(&input_q[..7], &input_p, &mut output, 4, &mut workspace),
            }))
            .is_err()
        );
        assert!(output.iter().all(|&value| value == u64::MAX));
    }
    let mut workspace = hps.workspace(0);
    hps.expand_q_to_p(&[], &mut [], 0, &mut workspace);
    hps.expand_p_to_q(&[], &mut [], 0, &mut workspace);
    hps.scale_q_to_p(&[], &mut [], 0, &mut workspace);
    hps.scale_and_round(&[], &[], &mut [], 0, &mut workspace);
}

#[test]
fn scale_and_round_resolves_wide_and_single_limb_p_half_boundaries() {
    // Covers both >u128 P and a single P just below the u64 NTT limit;
    // low bits above the f64 mantissa remain significant in the exact oracle.
    for p_moduli in [&WIDE_P[..], &[(1_u64 << 62) - 57][..]] {
        let p = big_product(p_moduli);
        let half = &p / 2_u8;
        let values: Vec<_> = [-7_i8, 0, 9]
            .iter()
            .flat_map(|&quotient| {
                let center = &p * IBig::from(quotient) + &half;
                (-2_i8..=2).map(move |step| &center + IBig::from(step))
            })
            .chain([IBig::ZERO, IBig::ONE, -IBig::ONE])
            .collect();
        let input_q = big_residues(&values, &WIDE_Q);
        let input_p = big_residues(&values, p_moduli);
        for t in [1_u64, 2, 65_537, u64::MAX] {
            let hps = HpsRns::try_new(&base(&WIDE_Q), &base(p_moduli), t).unwrap();
            let mut workspace = hps.workspace(values.len());
            let mut output = vec![0; input_q.len()];
            hps.scale_and_round(
                &input_q,
                &input_p,
                &mut output,
                values.len(),
                &mut workspace,
            );
            let expected: Vec<_> = values
                .iter()
                .map(|value| big_nearest(&(value * t), &p))
                .collect();
            assert_eq!(output, big_residues(&expected, &WIDE_Q));
        }
    }
}

#[test]
fn centered_converter_has_its_own_exact_batch_and_workspace_contract() {
    use primus_rns::{BaseConverter, CenteredBaseConverter};
    let q = big_product(&WIDE_Q);
    let half = &q / 2_u8;
    let values = vec![
        &half - 1_u8,
        half.clone(),
        &half + 1_u8,
        &q - 1_u8,
        IBig::ZERO,
        IBig::from((1u64 << 53) + 1),
    ];
    let centered: Vec<_> = values
        .iter()
        .map(|x| {
            let r = x % &q;
            if r > half { r - &q } else { r }
        })
        .collect();
    // The centered lift reuses the same direction's approximate conversion
    // resources; it must still resolve exact multiword half boundaries.
    let approximate = BaseConverter::new(&base(&WIDE_Q), &base(&WIDE_P));
    let converter = CenteredBaseConverter::try_from_converter(approximate.clone()).unwrap();
    let input = big_residues(&values, &WIDE_Q);
    let mut output = vec![0; WIDE_P.len() * values.len()];
    let mut workspace = converter.workspace(values.len());
    converter.convert_to(&input, &mut output, values.len(), &mut workspace);
    assert_eq!(output, big_residues(&centered, &WIDE_P));
    for bad_len in [0, input.len() - 1, input.len() + 1] {
        output.fill(77);
        assert!(
            catch_unwind(AssertUnwindSafe(|| converter.convert_to(
                &vec![0; bad_len],
                &mut output,
                values.len(),
                &mut workspace
            )))
            .is_err()
        );
        assert!(output.iter().all(|&x| x == 77));
    }
    let mut wrong = converter.workspace(values.len() - 1);
    assert!(
        catch_unwind(AssertUnwindSafe(|| converter.convert_to(
            &input,
            &mut output,
            values.len(),
            &mut wrong
        )))
        .is_err()
    );
    assert!(output.iter().all(|&x| x == 77));
    converter.convert_to(&[], &mut [], 0, &mut converter.workspace(0));
    assert!(CenteredBaseConverter::try_new(&base(&[16]), &base(&[19])).is_err());
    let unsupported = BaseConverter::new(&base(&[16]), &base(&[19]));
    assert!(CenteredBaseConverter::try_from_converter(unsupported).is_err());
}

#[test]
fn single_prime_centered_conversion_matches_signed_residues() {
    use primus_rns::CenteredBaseConverter;

    let q = (1_u64 << 61) - 1;
    let half = q / 2;
    let input = [0, 1, half - 1, half, half + 1, half + 2, q - 1];
    let centered = input.map(|value| {
        if value > half {
            i128::from(value) - i128::from(q)
        } else {
            i128::from(value)
        }
    });
    for p in [half - 2, half, half + 2, q - 2, q, q + 2] {
        let converter = CenteredBaseConverter::try_new(&base(&[q]), &base(&[p])).unwrap();
        let mut output = [0; 7];
        converter.convert_to(
            &input,
            &mut output,
            input.len(),
            &mut converter.workspace(input.len()),
        );
        assert_eq!(output.as_slice(), residues(&centered, &[p]));
    }
}
