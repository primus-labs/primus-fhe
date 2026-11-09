use primus_modulus::BarrettModulus;
use primus_rns::Residues;
use primus_rns::{BaseConverter, RNSBase};
use std::panic::{AssertUnwindSafe, catch_unwind};

type Value = u64;
type Modulus = BarrettModulus<Value>;
type Base = RNSBase<Value, Modulus>;

fn base(moduli: &[Value]) -> Base {
    let moduli: Vec<_> = moduli.iter().copied().map(Modulus::new).collect();
    Base::new(&moduli).unwrap()
}

#[test]
fn fast_conversion_matches_independent_crt_sum() {
    let source_moduli = [17, 19, 23];
    let input_base = base(&source_moduli);
    // Adjusted source residues can exceed both destination moduli.
    let output_base = base(&[5, 7]);
    let converter = BaseConverter::new(&input_base, &output_base);
    let input = [
        0, 1, 16, 7, // mod 17
        0, 2, 18, 11, // mod 19
        0, 3, 22, 13, // mod 23
    ];
    let value_count = input.len() / input_base.moduli_count();
    // An independent small-integer CRT sum: Q fits in u64, and inverses are
    // found by enumeration rather than using the converter's prepared factors.
    let q: u64 = source_moduli.iter().product();
    let lifts: Vec<u64> = (0..value_count)
        .map(|value_index| {
            source_moduli
                .iter()
                .enumerate()
                .map(|(i, &qi)| {
                    let punctured = q / qi;
                    let inverse = (1..qi)
                        .find(|&candidate| candidate * punctured % qi == 1)
                        .unwrap();
                    let adjusted = input[i * value_count + value_index] * inverse % qi;
                    adjusted * punctured
                })
                .sum()
        })
        .collect();
    let expected: Vec<_> = [5, 7]
        .iter()
        .flat_map(|&p| lifts.iter().map(move |&lift| lift % p))
        .collect();

    for value_index in 0..value_count {
        let value_residues = [
            input[value_index],
            input[value_count + value_index],
            input[2 * value_count + value_index],
        ];
        let mut scalar_output = vec![0; output_base.moduli_count()];
        let mut scalar_scratch = vec![0; input_base.moduli_count()];
        converter.fast_convert(
            Residues(value_residues.as_slice()),
            Residues(scalar_output.as_mut_slice()),
            &mut scalar_scratch,
        );
        for (modulus_index, value) in scalar_output.into_iter().enumerate() {
            assert_eq!(value, expected[modulus_index * value_count + value_index]);
        }
    }

    let mut output = vec![0; expected.len()];
    let required_scratch_len = converter.fast_convert_array_scratch_len(value_count);
    let mut scratch = vec![Value::MAX; required_scratch_len + 3];
    converter.fast_convert_array(&input, &mut output, value_count, &mut scratch);
    assert_eq!(output, expected);
    let paired: Vec<_> = converter
        .fast_convert_array_to_pair_iter(&input, value_count, &mut scratch)
        .collect();
    let expected_pairs: Vec<_> = lifts.iter().map(|&lift| (lift % 5, lift % 7)).collect();
    assert_eq!(paired, expected_pairs);
    assert_eq!(&scratch[required_scratch_len..], &[Value::MAX; 3]);
}

#[test]
fn fast_conversion_validates_complete_arrays_before_writes() {
    // The internal limb writer trusts the public array boundary for both kernels.
    for source in [&[17][..], &[17, 19, 23][..]] {
        let converter = BaseConverter::new(&base(source), &base(&[5, 7]));
        let n = 4;
        let input_len = source.len() * n;
        let output_len = 2 * n;
        let scratch_len = converter.fast_convert_array_scratch_len(n);
        let mut invalid_shapes = vec![
            (n, input_len - 1, output_len, scratch_len),
            (n, input_len + 1, output_len, scratch_len),
            (n, input_len, output_len - 1, scratch_len),
            (n, input_len, output_len + 1, scratch_len),
            (usize::MAX, 0, 0, 0),
        ];
        if scratch_len != 0 {
            invalid_shapes.push((n, input_len, output_len, scratch_len - 1));
        }
        for (n, input_len, output_len, scratch_len) in invalid_shapes {
            let input = vec![0; input_len];
            let mut output = vec![Value::MAX; output_len];
            let mut scratch = vec![Value::MAX; scratch_len];
            assert!(
                catch_unwind(AssertUnwindSafe(|| converter.fast_convert_array(
                    &input,
                    &mut output,
                    n,
                    &mut scratch,
                )))
                .is_err()
            );
            assert!(output.iter().all(|&value| value == Value::MAX));
            assert!(scratch.iter().all(|&value| value == Value::MAX));
        }
    }
}

#[test]
fn single_input_fast_and_corrected_conversion_use_distinct_lifts() {
    let input_base = base(&[17]);
    let fast_output_base = base(&[13, 19]);
    let fast_converter = BaseConverter::new(&input_base, &fast_output_base);
    let input = [0, 1, 8, 9, 16];
    let mut fast_output = [Value::MAX; 10];
    let mut fast_scratch = [Value::MAX; 5];

    fast_converter.fast_convert_array(&input, &mut fast_output, input.len(), &mut fast_scratch);

    assert_eq!(fast_output, [0, 1, 8, 9, 3, 0, 1, 8, 9, 16]);
    assert_eq!(fast_scratch, [Value::MAX; 5]);
    for &value in &input {
        let mut scalar_output = [Value::MAX; 2];
        fast_converter.fast_convert(
            Residues(&[value]),
            Residues(&mut scalar_output),
            &mut fast_scratch,
        );
        assert_eq!(scalar_output, [value % 13, value % 19]);
    }
    let pairs: Vec<_> = fast_converter
        .fast_convert_array_to_pair_iter(&input, input.len(), &mut fast_scratch)
        .collect();
    assert_eq!(pairs, [(0, 0), (1, 1), (8, 8), (9, 9), (3, 16)]);
    assert_eq!(fast_scratch, [Value::MAX; 5]);

    let corrected_output_base = base(&[13]);
    let corrected_converter = BaseConverter::new(&input_base, &corrected_output_base);
    let mut corrected_output = [Value::MAX; 5];
    let mut workspace = corrected_converter.corrected_conversion_workspace(input.len());

    corrected_converter.corrected_convert_array(
        &input,
        &mut corrected_output,
        input.len(),
        &mut workspace,
    );

    assert_eq!(corrected_output, [0, 1, 8, 5, 12]);
}

#[test]
fn corrected_array_conversion_uses_centered_values_and_reuses_workspace() {
    // 7428 = 17*19*23 - 1 represents -1, hence 4 modulo the destination 5.
    // Each source modulus exceeds the destination in this corrected path too.
    let input_moduli = [17, 19, 23];
    let input_base = base(&input_moduli);
    let output_base = base(&[5]);
    let converter = BaseConverter::new(&input_base, &output_base);
    let values = [0, 1, 2, 7, 16, 3_714, 3_715, 7_428];
    let input: Vec<_> = input_moduli
        .iter()
        .flat_map(|&modulus| values.iter().map(move |&value| value % modulus))
        .collect();
    let mut output = vec![Value::MAX; values.len()];
    let mut workspace = converter.corrected_conversion_workspace(values.len());

    converter.corrected_convert_array(&input, &mut output, values.len(), &mut workspace);
    assert_eq!(output, [0, 1, 2, 2, 1, 4, 1, 4]);

    output.fill(Value::MAX);
    converter.corrected_convert_array(&input, &mut output, values.len(), &mut workspace);
    assert_eq!(output, [0, 1, 2, 2, 1, 4, 1, 4]);
}

#[test]
fn empty_conversion_batches_keep_scratch_and_validate_shapes() {
    for source in [&[17][..], &[17, 19, 23][..]] {
        let input_base = base(source);
        let converter = BaseConverter::new(&input_base, &base(&[5, 7]));
        let mut scratch = [Value::MAX; 3];
        converter.fast_convert_array(&[], &mut [], 0, &mut scratch);
        assert_eq!(
            converter
                .fast_convert_array_to_pair_iter(&[], 0, &mut scratch)
                .count(),
            0,
        );
        assert_eq!(scratch, [Value::MAX; 3]);

        let corrected = BaseConverter::new(&input_base, &base(&[5]));
        let mut workspace = corrected.corrected_conversion_workspace(0);
        corrected.corrected_convert_array(&[], &mut [], 0, &mut workspace);
        // Empty input does not relax the single-output-basis requirement.
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                converter.corrected_convert_array(&[], &mut [], 0, &mut workspace);
            }))
            .is_err()
        );
        if source.len() > 1 {
            let mut nonempty_workspace = corrected.corrected_conversion_workspace(1);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    corrected.corrected_convert_array(&[], &mut [], 0, &mut nonempty_workspace);
                }))
                .is_err()
            );
        }
    }
}

#[test]
fn corrected_conversion_rejects_shapes_before_writing() {
    // The general path must validate its own workspace; the single-input
    // specialization intentionally ignores it. Neither writes partial output
    // on a layout failure.
    for source in [&[17][..], &[17, 19, 23][..]] {
        let converter = BaseConverter::new(&base(source), &base(&[5]));
        let value_count = 3;
        let input_len = source.len() * value_count;
        for (count, input_len, output_len) in [
            (value_count, input_len - 1, value_count),
            (value_count, input_len, value_count + 1),
            (usize::MAX, 0, 0),
        ] {
            let input = vec![0; input_len];
            let mut output = vec![Value::MAX; output_len];
            let mut workspace = converter.corrected_conversion_workspace(value_count);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    converter.corrected_convert_array(&input, &mut output, count, &mut workspace);
                }))
                .is_err()
            );
            assert!(output.iter().all(|&value| value == Value::MAX));
        }
        if source.len() > 1 {
            let mut output = [Value::MAX; 3];
            // Same value count, different number of input moduli.
            let other = BaseConverter::new(&base(&[17, 19]), &base(&[5]));
            let mut workspace = other.corrected_conversion_workspace(value_count);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    converter.corrected_convert_array(
                        &vec![0; input_len],
                        &mut output,
                        value_count,
                        &mut workspace,
                    );
                }))
                .is_err()
            );
            assert_eq!(output, [Value::MAX; 3]);
        }
    }
}
