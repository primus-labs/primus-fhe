use core::range::Range;

use primus_modulus::BarrettModulus;
use primus_rns::{HybridRNS, HybridRNSPartitioning, RnsError};
use std::panic::{AssertUnwindSafe, catch_unwind};

type ValueT = u64;
type ModulusT = BarrettModulus<ValueT>;

fn make_hybrid(
    q: &[ValueT],
    p: &[ValueT],
    decomposition_count: usize,
) -> HybridRNS<ValueT, ModulusT> {
    let q_moduli: Vec<_> = q.iter().copied().map(ModulusT::new).collect();
    let p_moduli: Vec<_> = p.iter().copied().map(ModulusT::new).collect();
    HybridRNS::new(&q_moduli, &p_moduli, decomposition_count).unwrap()
}

#[test]
fn construction_uses_fixed_partitioning_and_precomputes_p() {
    // Dropping active Q limbs must not repartition surviving key-switch digits.
    let q_moduli = [17, 41, 73, 89, 97].map(ModulusT::new);
    let p_moduli = [101, 103].map(ModulusT::new);
    let hybrid = HybridRNS::new(&q_moduli, &p_moduli, 3).unwrap();
    let ranges: Vec<_> = hybrid
        .partitions()
        .map(|partition| partition.q_range())
        .collect();

    assert_eq!(hybrid.decomposition_count(), 3);
    assert_eq!(hybrid.partition_moduli_count(), 2);
    assert_eq!(hybrid.partitioning().full_q_moduli_count(), 5);
    assert_eq!(
        ranges,
        [Range::from(0..2), Range::from(2..4), Range::from(4..5)],
    );

    let partitioning = hybrid.partitioning();
    let active = HybridRNS::from_partitioning(&q_moduli[..3], &p_moduli, partitioning).unwrap();
    let active_ranges: Vec<_> = active
        .partitions()
        .map(|partition| partition.q_range())
        .collect();
    assert_eq!(active.partitioning(), partitioning);
    assert_eq!(active.decomposition_count(), 3);
    assert_eq!(active.partition_count(), 2);
    assert_eq!(active_ranges, [Range::from(0..2), Range::from(2..3)]);

    assert!(matches!(
        HybridRNSPartitioning::new(5, 4),
        Err(RnsError::IncompatibleDecompositionCount {
            q_moduli_count: 5,
            decomposition_count: 4,
        }),
    ));
    assert!(matches!(
        HybridRNS::from_partitioning(
            &q_moduli,
            &p_moduli,
            HybridRNSPartitioning::new(4, 2).unwrap(),
        ),
        Err(RnsError::ActiveBaseTooLarge {
            actual: 5,
            maximum: 4,
        }),
    ));
    assert_eq!(hybrid.p_mod_q(), [16, 30, 37, 79, 24]);
    assert_eq!(hybrid.inv_p_mod_q(), [16, 26, 2, 80, 93]);
}

#[test]
fn mod_up_full_and_streaming_outputs_match() {
    let hybrid = make_hybrid(&[17, 41, 73], &[89, 97], 2);
    let poly_length = 4;
    let polynomial_q = [
        1, 2, 3, 4, // q_0
        11, 12, 13, 14, // q_1
        21, 22, 23, 24, // q_2
    ];
    // For each partition, lift a_i with sum((a_i * (Q/q_i)^-1 mod q_i) * Q/q_i)
    // without reducing modulo the partition product Q. For the first column
    // in partition 0 this is 5*41 + 32*17 = 749; partition 1 lifts 21 directly.
    let expected_digits: [[ValueT; 20]; 2] = [
        [
            1, 2, 3, 4, // q_0: copied
            11, 12, 13, 14, // q_1: copied
            19, 20, 21, 22, // q_2: converted
            37, 38, 39, 40, // p_0: converted
            70, 71, 72, 73, // p_1: converted
        ],
        [
            4, 5, 6, 7, // q_0: converted
            21, 22, 23, 24, // q_1: converted
            21, 22, 23, 24, // q_2: copied
            21, 22, 23, 24, // p_0: converted
            21, 22, 23, 24, // p_1: converted
        ],
    ];

    for (partition, expected) in hybrid.partitions().zip(&expected_digits) {
        let q_range = partition.q_range();
        let partition_elements =
            Range::from(q_range.start * poly_length..q_range.end * poly_length);

        let mut digit_qp = vec![0; hybrid.qp_moduli_count() * poly_length];
        let mut scratch = vec![0; partition.mod_up_scratch_len(poly_length)];
        partition.approx_mod_up_to(&polynomial_q, &mut digit_qp, poly_length, &mut scratch);
        assert_eq!(digit_qp, expected);
        if !scratch.is_empty() {
            let mut invalid_scratch = vec![ValueT::MAX; scratch.len() - 1];
            let mut invalid_digit = vec![ValueT::MAX; digit_qp.len()];
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    partition.approx_mod_up_to(
                        &polynomial_q,
                        &mut invalid_digit,
                        poly_length,
                        &mut invalid_scratch,
                    );
                }))
                .is_err()
            );
            assert!(invalid_digit.iter().all(|&value| value == ValueT::MAX));
            assert!(invalid_scratch.iter().all(|&value| value == ValueT::MAX));
        }

        let mut streamed = vec![0; hybrid.qp_moduli_count() * poly_length];
        streamed[partition_elements].copy_from_slice(&polynomial_q[partition_elements]);
        let mut output_limb = vec![0; poly_length];
        partition.for_each_approx_mod_up_complement_limb(
            &polynomial_q,
            &mut output_limb,
            poly_length,
            &mut scratch,
            |modulus_index, converted_limb| {
                let limb_start = modulus_index * poly_length;
                streamed[limb_start..limb_start + poly_length].copy_from_slice(converted_limb);
            },
        );
        assert_eq!(streamed, expected);

        // Streaming writes one caller-owned limb repeatedly. Reject a malformed
        // limb before the private writer or callback can consume a partial one.
        for output_len in [poly_length - 1, poly_length + 1] {
            let mut output = vec![ValueT::MAX; output_len];
            let mut consumed = false;
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    partition.for_each_approx_mod_up_complement_limb(
                        &polynomial_q,
                        &mut output,
                        poly_length,
                        &mut scratch,
                        |_, _| consumed = true,
                    );
                }))
                .is_err()
            );
            assert!(!consumed);
            assert!(output.iter().all(|&value| value == ValueT::MAX));
        }
    }
}

#[test]
fn mod_down_matches_expected_output() {
    // Lift P without reducing modulo its product, then compute (x_Q-lift)/P.
    // Column 0 lifts to 24 for P=[89], and to 3*97 + 81*89 = 7500 for P=[89,97].
    let cases = [
        (
            &[89][..],
            [16, 16, 16, 16, 16, 39, 39, 39, 39, 39, 68, 68, 68, 68, 68],
        ),
        (
            &[89, 97][..],
            [0, 0, 0, 16, 0, 38, 38, 38, 37, 38, 48, 48, 48, 47, 48],
        ),
    ];
    for (p_moduli, expected_q) in cases {
        let hybrid = make_hybrid(&[17, 41, 73], p_moduli, 2);
        let poly_length = 5;
        let mut polynomial_qp = vec![0; hybrid.qp_moduli_count() * poly_length];
        let qp_moduli = [17, 41, 73].iter().chain(p_moduli);

        for (modulus_index, (limb, &modulus)) in polynomial_qp
            .chunks_exact_mut(poly_length)
            .zip(qp_moduli)
            .enumerate()
        {
            for (coefficient, value) in limb.iter_mut().enumerate() {
                *value = (7 * modulus_index + 11 * coefficient + 3) as u64 % modulus;
            }
        }

        let original = polynomial_qp.clone();
        let q_len = hybrid.q_moduli_count() * poly_length;
        let mut converted_p = vec![0; hybrid.q_moduli_count() * poly_length];
        let scratch_len = hybrid.mod_down_scratch_len(poly_length);
        let mut scratch = vec![ValueT::MAX; scratch_len + 3];
        hybrid.approx_mod_down_q_assign(
            &mut polynomial_qp,
            poly_length,
            &mut converted_p,
            &mut scratch,
        );

        assert_eq!(&polynomial_qp[..q_len], expected_q);
        assert_eq!(&polynomial_qp[q_len..], &original[q_len..]);

        // The independently callable conversion and correction must also reproduce
        // the complete ModDown, with no hidden state from its internal kernels.
        let mut separate_q = original[..q_len].to_vec();
        hybrid.approx_convert_p_to_q_to(
            &original[q_len..],
            &mut converted_p,
            poly_length,
            &mut scratch,
        );
        hybrid.approx_mod_down_from_correction_q_assign(&mut separate_q, &converted_p, poly_length);
        assert_eq!(separate_q, expected_q);
        // A single P limb ignores scratch entirely; general conversion only writes its prefix.
        assert_eq!(&scratch[scratch_len..], &[ValueT::MAX; 3]);

        // A public weight can change the prepared correction before the common
        // final step. This checks the modular identity, not a BGV scheme.
        let weighted: Vec<_> = converted_p
            .chunks_exact(poly_length)
            .zip([17, 41, 73])
            .flat_map(|(limb, modulus)| limb.iter().map(move |&value| 3 * value % modulus))
            .collect();
        let mut weighted_q = original[..q_len].to_vec();
        hybrid.approx_mod_down_from_correction_q_assign(&mut weighted_q, &weighted, poly_length);
        for (modulus_index, qi) in [17, 41, 73].into_iter().enumerate() {
            // Enumerate P^-1 as an independent small-integer oracle.
            let p: u64 = p_moduli.iter().product();
            let inverse = (1..qi)
                .find(|&candidate| candidate * (p % qi) % qi == 1)
                .unwrap();
            for coefficient in 0..poly_length {
                let index = modulus_index * poly_length + coefficient;
                let expected = ((original[index] + qi - weighted[index]) * inverse) % qi;
                assert_eq!(weighted_q[index], expected);
            }
        }
    }
}

#[test]
fn mod_down_validates_public_buffers_before_writes() {
    let hybrid = make_hybrid(&[17, 41], &[89, 97], 1);
    // Q and P each contain two limbs. Exercise each public entry directly:
    // none may depend on validation performed by a previous operation.
    for (n, q_len, p_len, scratch_len) in [
        (2, 3, 4, 4),
        (2, 5, 4, 4),
        (2, 4, 3, 4),
        (2, 4, 5, 4),
        (2, 4, 4, 3),
        (usize::MAX, 0, 0, 0),
    ] {
        let mut qp = vec![0; q_len + p_len];
        let mut correction = vec![ValueT::MAX; q_len];
        let mut scratch = vec![ValueT::MAX; scratch_len];
        assert!(
            catch_unwind(AssertUnwindSafe(|| hybrid.approx_mod_down_q_assign(
                &mut qp,
                n,
                &mut correction,
                &mut scratch,
            )))
            .is_err()
        );
        assert!(qp.iter().all(|&value| value == 0));
        assert!(correction.iter().all(|&value| value == ValueT::MAX));
        assert!(scratch.iter().all(|&value| value == ValueT::MAX));

        assert!(
            catch_unwind(AssertUnwindSafe(|| hybrid.approx_convert_p_to_q_to(
                &qp[q_len..],
                &mut correction,
                n,
                &mut scratch,
            )))
            .is_err()
        );
        assert!(correction.iter().all(|&value| value == ValueT::MAX));
        assert!(scratch.iter().all(|&value| value == ValueT::MAX));
    }

    // A caller may supply correction directly, without calling P -> Q first.
    for (n, q_len, correction_len) in [(2, 3, 4), (2, 4, 3), (2, 4, 5), (usize::MAX, 0, 0)] {
        let mut q = vec![0; q_len];
        let correction = vec![0; correction_len];
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                hybrid.approx_mod_down_from_correction_q_assign(&mut q, &correction, n);
            }))
            .is_err()
        );
        assert!(q.iter().all(|&value| value == 0));
    }
}

#[test]
fn empty_hybrid_operations_do_not_write_or_consume_limbs() {
    // Cover both P-conversion kernels and both singleton/general partitions.
    for p_moduli in [&[89][..], &[89, 97][..]] {
        let hybrid = make_hybrid(&[17, 41, 73], p_moduli, 2);
        let mut scratch = [ValueT::MAX; 3];
        hybrid.approx_mod_down_q_assign(&mut [], 0, &mut [], &mut scratch);
        hybrid.approx_convert_p_to_q_to(&[], &mut [], 0, &mut scratch);
        hybrid.approx_mod_down_from_correction_q_assign(&mut [], &[], 0);
        for partition in hybrid.partitions() {
            partition.approx_mod_up_to(&[], &mut [], 0, &mut scratch);
            partition.for_each_approx_mod_up_complement_limb(
                &[],
                &mut [],
                0,
                &mut scratch,
                |_, _| panic!("empty ModUp must not consume a limb"),
            );
        }
        assert_eq!(scratch, [ValueT::MAX; 3]);
    }
}
