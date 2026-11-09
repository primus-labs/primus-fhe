//! Independent coefficient phases, rounding and key-entry noise for NTRU -> LWE.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::PlaintextEmbedding;
use primus_lattice::LweDimension;
use primus_shape::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::{AsInto, FheUint};
use primus_lattice::lwe::LweIter;
use primus_lwe::{LweCiphertext, LweKeySwitchingParameters, LweParameters, LweSecretKey};
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_ntru::{
    LweReturnEvaluator, NtruCiphertext, NtruLweKeySwitchingKey, NtruSecretKey, SecretKeyDistr,
};
use primus_reduce::{Modulus, RingContext};
use rand::{Rng, SeedableRng, rngs::StdRng};

const N: usize = 32;
const F: [i128; N] = {
    let mut secret = [0; N];
    secret[0] = 1;
    secret[1] = -1;
    secret[3] = 1;
    secret[6] = -1;
    secret[7] = 1;
    secret
};
// Even signed sum: this target cannot be padded into an invertible native NTRU key.
const S: [i128; 5] = [1, -1, 0, 1, -1];

// Represent native and explicit moduli uniformly, including 2^64.
fn modulus_value<T: FheUint, M: Modulus<ValueT = T>>(modulus: M) -> u128 {
    modulus
        .explicit_value()
        .map_or(1u128 << T::BITS, |q| q.as_into())
}

// Choose a signed representative for circular phase-error comparisons.
fn center(value: i128, q: i128) -> i128 {
    (value + q / 2).rem_euclid(q) - q / 2
}

// u128 covers the exact biased product even for Q=q=2^64 and c=2^64-1.
fn rounded(value: u128, source: u128, target: u128) -> u128 {
    ((value * target + source / 2) / source) % target
}

// Independent negacyclic coefficient of f*c under the fixed signed secret F.
fn ring_phase(input: &[u128], index: usize, q: u128) -> i128 {
    let n = input.len();
    F.iter()
        .enumerate()
        .map(|(i, &f)| {
            let j = (index + n - i) % n;
            let v = input[j] as i128 * f;
            if i <= index { v } else { -v }
        })
        .sum::<i128>()
        .rem_euclid(q as i128)
}

// Independent b-<a,S> phase under the target secret.
fn lwe_phase(input: &[u128], q: u128) -> i128 {
    (input[S.len()] as i128
        - input[..S.len()]
            .iter()
            .zip(S)
            .map(|(&a, s)| a as i128 * s)
            .sum::<i128>())
    .rem_euclid(q as i128)
}

// Cache one key's rows and observed row noise for independent integer accumulation.
// Gadget decomposition is shared with the basis API; products, modular sums and
// negacyclic phase checks are computed with u128/i128 instead of the return kernel.
struct ReturnOracle<'a, T: FheUint> {
    basis: &'a ApproxSignedBasis<T>,
    q: u128,
    scalars: Vec<u128>,
    entries: Vec<Vec<u128>>,
    row_noise: Vec<i128>,
}

impl<'a, T: FheUint> ReturnOracle<'a, T> {
    // Decode the stored key rows once, reusing them for every input and coefficient.
    fn new(key: &'a NtruLweKeySwitchingKey<T>, q: u128) -> Self {
        let basis = key.basis();
        let levels = basis.level_count().get();
        let scalars: Vec<u128> = basis.scalar_iter().map(|v| v.as_into()).collect();
        let entries: Vec<Vec<u128>> = LweIter::new(key.as_slice(), S.len() + 1)
            .map(|row| row.as_ref().iter().map(|&v| v.as_into()).collect())
            .collect();
        let row_noise: Vec<i128> = entries
            .iter()
            .enumerate()
            .map(|(j, row)| {
                center(
                    lwe_phase(row, q) - scalars[j % levels] as i128 * F[j / levels],
                    q as i128,
                )
            })
            .collect();
        Self {
            basis,
            q,
            scalars,
            entries,
            row_noise,
        }
    }

    // Check exact ciphertext coefficients and the phase error from rounding,
    // decomposition residuals and the actual sampled key-entry noise.
    fn assert_output(
        &self,
        raw: &[u128],
        switched: &[u128],
        source_q: u128,
        index: usize,
        output: &LweCiphertext<T>,
    ) {
        let q = self.q;
        let levels = self.basis.level_count().get();
        let input_phase = ring_phase(switched, index, q);
        let scaled_phase = rounded(ring_phase(raw, index, source_q) as u128, source_q, q) as i128;
        // Each coefficient rounds within 1/2; rounding the phase adds at most 1/2.
        assert!(
            2 * center(input_phase - scaled_phase, q as i128).abs()
                <= F.iter().map(|v| v.abs()).sum::<i128>() + 1
        );
        let mask: Vec<_> = (0..F.len())
            .map(|i| {
                let v = switched[(index + F.len() - i) % F.len()];
                if i <= index { (q - v) % q } else { v }
            })
            .collect();
        // Build the output from independent integer sums of the stored LWE rows.
        let mut expected = vec![0u128; S.len() + 1];
        let mut phase_error = 0i128;
        let mut bound = 0i128;
        for (i, &a) in mask.iter().enumerate() {
            let (adjusted, mut carry) = self.basis.init_value_carry(T::as_from(a));
            let mut reconstructed = 0u128;
            for (level, decomposer) in self.basis.decomposer_iter().enumerate() {
                let (digit, next) = decomposer.decompose(adjusted, carry);
                carry = next;
                let d: u128 = digit.as_into();
                let row = i * levels + level;
                for (out, &v) in expected.iter_mut().zip(&self.entries[row]) {
                    *out = (*out + q - (d * v) % q) % q;
                }
                reconstructed = (reconstructed + (d * self.scalars[level]) % q) % q;
                let term = center(d as i128, q as i128) * self.row_noise[row];
                phase_error -= term;
                bound += term.abs();
            }
            let residual = center(a as i128 - reconstructed as i128, q as i128);
            phase_error += residual * F[i];
            bound += (residual * F[i]).abs();
        }
        let actual: Vec<u128> = output.as_ref().iter().map(|&v| v.as_into()).collect();
        assert_eq!(actual, expected);
        assert!(actual.iter().all(|&v| v < q));
        assert_eq!(
            lwe_phase(&actual, q),
            (input_phase + phase_error).rem_euclid(q as i128)
        );
        assert!(center(lwe_phase(&actual, q) - input_phase, q as i128).abs() <= bound);
        // This fixed fixture's observed-entry bound is nonvacuous, not a tail estimate.
        assert!(bound < q as i128 / 8);
    }
}

// Exercise wrap, half ties, negacyclic signs and a final zero input after dirty reuse.
fn coefficient_inputs<T: FheUint>(source_q: u128, q: u128) -> Vec<NtruCiphertext<Vec<T>>> {
    let edges = [
        0,
        1,
        source_q - 1,
        source_q / 2,
        source_q / 2 - 1,
        (source_q / q.min(source_q)) / 2,
        source_q - 2,
        source_q / 3,
    ];
    (0..4)
        .map(|round| {
            NtruCiphertext::new(
                (0..F.len())
                    .map(|i| {
                        T::as_from(if round == 3 {
                            0
                        } else {
                            edges[(i + round) % edges.len()]
                        })
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

// Establish an integer-checked result for each source/index pair. Later batch
// comparisons reuse these ciphertexts, so their oracle is not another batch path.
fn check_scalar_returns<T: FheUint, M: RingContext<T>>(
    key: &NtruLweKeySwitchingKey<T>,
    inputs: &[NtruCiphertext<Vec<T>>],
    source_q: u128,
    target: M,
) -> Vec<Vec<LweCiphertext<T>>> {
    let q = modulus_value::<T, _>(target);
    let oracle = ReturnOracle::new(key, q);
    let evaluator = LweReturnEvaluator::new(key, target);
    let mut workspace = evaluator.new_scalar_workspace();
    let mut output = LweCiphertext::<T>::new(vec![T::ONE; S.len() + 1]);
    let mut expected_inputs = Vec::new();
    for input in inputs {
        let raw: Vec<u128> = input.as_ref().iter().map(|&v| v.as_into()).collect();
        let switched: Vec<_> = raw.iter().map(|&v| rounded(v, source_q, q)).collect();
        let mut expected = vec![output.clone(); F.len()];
        for index in (0..F.len()).rev() {
            evaluator.return_at_to(input.as_view(), index, output.as_mut_view(), &mut workspace);
            oracle.assert_output(&raw, &switched, source_q, index, &output);
            expected[index].as_mut().copy_from_slice(output.as_ref());
        }
        expected_inputs.push(expected);
    }
    expected_inputs
}

// Shared-input returns preserve repeated/nonmonotonic indices across two tiles
// and a tail. Singleton and empty requests reuse the same dirty buffers.
fn check_shared_input_returns<T: FheUint, M: RingContext<T>>(
    key: &NtruLweKeySwitchingKey<T>,
    inputs: &[NtruCiphertext<Vec<T>>],
    expected_inputs: &[Vec<LweCiphertext<T>>],
    target: M,
    outputs: &mut [LweCiphertext<T>],
) {
    let evaluator = LweReturnEvaluator::new(key, target);
    let mut workspace = evaluator.new_batch_workspace();
    for (input, expected) in inputs.iter().zip(expected_inputs) {
        for count in [17, 1, 0] {
            let indices = (0..count).map(|i| (3 * (i % 9) + 1) % F.len());
            let tail = outputs[count..].to_vec();
            evaluator.return_many_at_to(
                input.as_view(),
                indices.clone(),
                &mut outputs[..count],
                &mut workspace,
            );
            for (output, index) in outputs[..count].iter().zip(indices) {
                assert_eq!(output, &expected[index]);
            }

            // The bound prefix path uses the same scalar integer oracle and leaves
            // complete ciphertexts beyond the supplied output slice untouched.
            assert_eq!(&outputs[count..], tail);
            evaluator.return_prefix_to(input.as_view(), &mut outputs[..count], &mut workspace);
            assert_eq!(&outputs[..count], &expected[..count]);
            assert_eq!(&outputs[count..], tail);
        }
    }
}

// Streamed returns retain extracted LWEs while the single source buffer is
// overwritten before KS. A short final tile must ignore older slots past its end.
fn check_streamed_returns<T: FheUint, M: RingContext<T>>(
    key: &NtruLweKeySwitchingKey<T>,
    inputs: &[NtruCiphertext<Vec<T>>],
    expected_inputs: &[Vec<LweCiphertext<T>>],
    target: M,
    outputs: &mut [LweCiphertext<T>],
) {
    let evaluator = LweReturnEvaluator::new(key, target);
    let mut workspace = evaluator.new_batch_workspace();
    let mut current = NtruCiphertext::<Vec<T>>::zero(F.len());
    let capacity = workspace.batch_capacity();
    for count in [17, 1, 0] {
        let tail = outputs[count..].to_vec();
        for (tile, outputs) in outputs[..count].chunks_mut(capacity).enumerate() {
            workspace.begin_batch();
            for slot in 0..outputs.len() {
                let i = tile * capacity + slot;
                current
                    .as_mut()
                    .copy_from_slice(inputs[i % inputs.len()].as_ref());
                evaluator.append_at(current.as_view(), (3 * i + 1) % F.len(), &mut workspace);
                current.as_mut().fill(T::ZERO);
            }
            evaluator.return_batch_to(outputs, &mut workspace);
            assert!(!workspace.is_batch_active());
        }
        if count == 0 {
            workspace.begin_batch();
            evaluator.return_batch_to(&mut outputs[..0], &mut workspace);
            assert!(!workspace.is_batch_active());
        }
        assert_eq!(&outputs[count..], tail);
        for (i, output) in outputs[..count].iter().enumerate() {
            assert_eq!(
                output,
                &expected_inputs[i % inputs.len()][(3 * i + 1) % F.len()]
            );
        }
    }
}

// Generate each modulus/basis fixture once for all three return paths.
fn check_modulus_pair<T: FheUint, Q: Modulus<ValueT = T>, M: RingContext<T>>(source: Q, target: M) {
    let source_q = modulus_value::<T, _>(source);
    let q = modulus_value::<T, _>(target);
    let secret = NtruSecretKey::new(
        F.iter().map(|&v| v.as_into()).collect(),
        SecretKeyDistr::UniformTernary,
    );
    let output_secret = LweSecretKey::new(
        S.iter()
            .map(|&v| T::as_from(v.rem_euclid(q as i128)))
            .collect(),
        SecretKeyDistr::UniformTernary,
        target,
    );
    let parameters = LweParameters::new(
        LweDimension::new(S.len()),
        T::TWO,
        target,
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    let inputs = coefficient_inputs(source_q, q);
    let mut outputs = vec![LweCiphertext::new(vec![T::ONE; S.len() + 1]); 17];
    for level_count in [None, Some(2)] {
        let basis = ApproxSignedBasis::new(
            target.explicit_value(),
            DecompositionBaseLog::new(4),
            level_count.map(DecompositionLevelCount::new),
        );
        let key_parameters =
            LweKeySwitchingParameters::new(parameters.encryption_parameters().clone(), basis);
        let mut rng = StdRng::seed_from_u64(0x4e5452554c5745);
        let key = NtruLweKeySwitchingKey::generate(
            &secret,
            source,
            &output_secret,
            &key_parameters,
            &mut rng,
        );
        assert_eq!(key.input_modulus(), source.explicit_value());
        assert_eq!(key.poly_length(), F.len());
        assert_eq!(key.output_dimension(), LweDimension::new(S.len()));
        let expected = check_scalar_returns(&key, &inputs, source_q, target);
        check_shared_input_returns(&key, &inputs, &expected, target, &mut outputs);
        check_streamed_returns(&key, &inputs, &expected, target, &mut outputs);
    }
}

// Keep both word widths on the same source/target modulus and rounding matrix.
fn check_moduli<T: FheUint>() {
    let native = NativeModulus::<T>::new();
    let odd = BarrettModulus::new(T::as_from(65537u32));
    let source = BarrettModulus::new(T::as_from(132120577u32));
    let power = PowOf2Modulus::new(T::ONE << (T::BITS - 4));
    check_modulus_pair(native, native);
    check_modulus_pair(native, odd);
    check_modulus_pair(native, power);
    check_modulus_pair(source, odd);
    check_modulus_pair(source, source);
    check_modulus_pair(source, native);
    check_modulus_pair(BarrettModulus::new(T::as_from(131074u32)), odd); // half ties, including endpoint
    check_modulus_pair(
        PowOf2Modulus::new(T::ONE << (T::BITS - 2)),
        PowOf2Modulus::new(T::as_from(65536u32)),
    );
    check_modulus_pair(UintModulus::new(T::MAX), odd); // full-width explicit source; no narrowing
    check_modulus_pair(UintModulus::new(T::MAX), native);
}

// Scalar integer oracles also anchor the two batch paths at both word widths.
#[test]
fn coefficient_rounding_extraction_and_independent_lwe_key_switch() {
    check_moduli::<u32>();
    check_moduli::<u64>();
}

// Invalid scalar inputs leave the caller's output unchanged.
fn check_scalar_errors(key: &NtruLweKeySwitchingKey<u32>) {
    let evaluator = LweReturnEvaluator::new(key, BarrettModulus::new(65537));
    for (input_len, index, output_len) in [
        (0, 0, 4),
        (N - 1, 0, 4),
        (N + 1, 0, 4),
        (N, N, 4),
        (N, usize::MAX, 4),
        (N, 0, 0),
        (N, 0, 3),
        (N, 0, 5),
    ] {
        let input = NtruCiphertext::new(vec![9u32; input_len]);
        let mut output = LweCiphertext::new(vec![17u32; output_len]);
        let before = output.as_ref().to_vec();
        let mut workspace = evaluator.new_scalar_workspace();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.return_at_to(
                    input.as_view(),
                    index,
                    output.as_mut_view(),
                    &mut workspace,
                );
            }))
            .is_err()
        );
        assert_eq!(output.as_ref(), before);
    }
}

// Validate all indices and output shapes before any shared-input batch write.
fn check_shared_input_errors(key: &NtruLweKeySwitchingKey<u32>) {
    let evaluator = LweReturnEvaluator::new(key, BarrettModulus::new(65537));
    let mut workspace = evaluator.new_batch_workspace();
    // Reject the whole request even when only its last index or output is invalid.
    for (input_len, indices, output_lens) in [
        (N, [0, N], vec![4, 4]),
        (N, [0, 1], vec![4]),
        (N, [0, 1], vec![4, 4, 4]),
        (N, [0, 1], vec![4, 3]),
        (N - 1, [0, 1], vec![4, 4]),
    ] {
        let input = NtruCiphertext::new(vec![9u32; input_len]);
        let mut outputs: Vec<_> = output_lens
            .into_iter()
            .map(|len| LweCiphertext::new(vec![17u32; len]))
            .collect();
        let before = outputs.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.return_many_at_to(
                input.as_view(),
                indices.into_iter(),
                &mut outputs,
                &mut workspace,
            )))
            .is_err()
        );
        assert_eq!(outputs, before);
    }
}

// Bound streams retain their valid prefix on rejection and invalidate it on submission/discard.
fn check_bound_return_state(key: &NtruLweKeySwitchingKey<u32>) {
    let modulus = BarrettModulus::new(65537u32);
    assert!(catch_unwind(|| LweReturnEvaluator::new(key, BarrettModulus::new(65539u32))).is_err());
    let evaluator = LweReturnEvaluator::new(key, modulus);
    let mut workspace = evaluator.new_batch_workspace();
    let input = NtruCiphertext::new(vec![9u32; N]);
    let mut expected = LweCiphertext::zero(key.output_dimension().get());
    evaluator.return_at_to(
        input.as_view(),
        3,
        expected.as_mut_view(),
        &mut evaluator.new_scalar_workspace(),
    );
    let mut output = [LweCiphertext::new(vec![17; expected.as_ref().len()])];
    let untouched = output.clone();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            evaluator.append_at(input.as_view(), 3, &mut workspace);
        }))
        .is_err()
    );

    workspace.begin_batch();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            evaluator.return_prefix_to(input.as_view(), &mut output, &mut workspace);
        }))
        .is_err()
    );
    assert_eq!(output, untouched);
    evaluator.append_at(input.as_view(), 3, &mut workspace);
    for (input_len, index) in [(N - 1, 0), (N, N)] {
        let invalid = NtruCiphertext::new(vec![9; input_len]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.append_at(invalid.as_view(), index, &mut workspace);
            }))
            .is_err()
        );
    }
    let mut invalid_outputs = [LweCiphertext::new(vec![17; 3])];
    let before = invalid_outputs.clone();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            evaluator.return_batch_to(&mut invalid_outputs, &mut workspace);
        }))
        .is_err()
    );
    assert_eq!(invalid_outputs, before);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            evaluator.return_batch_to(&mut [], &mut workspace);
        }))
        .is_err()
    );
    assert!(workspace.is_batch_active());
    evaluator.return_batch_to(&mut output, &mut workspace);
    assert_eq!(output[0], expected);
    assert!(!workspace.is_batch_active());

    workspace.begin_batch();
    evaluator.append_at(input.as_view(), 0, &mut workspace);
    workspace.discard_batch();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            evaluator.return_batch_to(&mut output, &mut workspace);
        }))
        .is_err()
    );
    assert_eq!(output[0], expected);
    workspace.begin_batch();
    evaluator.return_batch_to(&mut [], &mut workspace);
    assert!(!workspace.is_batch_active());

    // Capacity rejection must retain the entire prepared tile for a retry.
    workspace.begin_batch();
    for _ in 0..workspace.batch_capacity() {
        evaluator.append_at(input.as_view(), 3, &mut workspace);
    }
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            evaluator.append_at(input.as_view(), 0, &mut workspace);
        }))
        .is_err()
    );
    let mut tile = vec![untouched[0].clone(); workspace.batch_capacity()];
    evaluator.return_batch_to(&mut tile, &mut workspace);
    assert!(tile.iter().all(|output| output == &expected));
}

// Storage can be reused across bindings, but each public return still validates
// its shape. A rejected submit through another binding must preserve the prefix.
fn check_bound_workspace_errors(key: &NtruLweKeySwitchingKey<u32>) {
    let modulus = BarrettModulus::new(65537u32);
    let evaluator = LweReturnEvaluator::new(key, modulus);
    let input = NtruCiphertext::new(vec![9; N]);
    for (n, dimension) in [(2 * N, 3), (N, 2)] {
        let parameters = LweKeySwitchingParameters::new(
            primus_lwe::LweEncryptionParameters::new(
                LweDimension::new(dimension),
                modulus,
                SecretKeyDistr::UniformBinary,
                0.7,
            ),
            key.basis().clone(),
        );
        let secret = NtruSecretKey::new(vec![1; n], SecretKeyDistr::UniformBinary);
        let mut rng = StdRng::seed_from_u64(12);
        let target = LweSecretKey::generate(parameters.output(), &mut rng);
        let other_key = NtruLweKeySwitchingKey::generate(
            &secret,
            NativeModulus::new(),
            &target,
            &parameters,
            &mut rng,
        );
        let other = LweReturnEvaluator::new(&other_key, modulus);
        let mut wrong_workspace = other.new_batch_workspace();
        let mut outputs = [LweCiphertext::new(vec![17; 4])];
        let before = outputs.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.return_many_at_to(
                    input.as_view(),
                    0..1,
                    &mut outputs,
                    &mut wrong_workspace,
                );
            }))
            .is_err()
        );
        assert_eq!(outputs, before);
        if n != N {
            let mut wrong_scalar = other.new_scalar_workspace();
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    evaluator.return_at_to(
                        input.as_view(),
                        0,
                        outputs[0].as_mut_view(),
                        &mut wrong_scalar,
                    );
                }))
                .is_err()
            );
            assert_eq!(outputs, before);
            wrong_workspace.begin_batch();
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    evaluator.append_at(input.as_view(), 0, &mut wrong_workspace);
                }))
                .is_err()
            );
            wrong_workspace.discard_batch();
        }

        let mut workspace = evaluator.new_batch_workspace();
        evaluator.return_prefix_to(input.as_view(), &mut outputs, &mut workspace);
        let expected = outputs.clone();
        workspace.begin_batch();
        evaluator.append_at(input.as_view(), 0, &mut workspace);
        let mut wrong_outputs = [LweCiphertext::new(vec![17; dimension + 1])];
        let before = wrong_outputs.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                other.return_batch_to(&mut wrong_outputs, &mut workspace);
            }))
            .is_err()
        );
        assert_eq!(wrong_outputs, before);
        assert!(workspace.is_batch_active());
        evaluator.return_batch_to(&mut outputs, &mut workspace);
        assert_eq!(outputs, expected);
    }
}

// Invalid key bindings must fail before consuming randomness.
fn check_generation_errors(params: &LweParameters<u32, BarrettModulus<u32>>) {
    let key_parameters = LweKeySwitchingParameters::new(
        params.encryption_parameters().clone(),
        ApproxSignedBasis::new(Some(65537), DecompositionBaseLog::new(4), None),
    );
    for (f, dimension, source_q) in [
        (65537, 3, 97),
        (-65537, 3, 97),
        (i32::MIN, 3, 97),
        (1, 2, 97),
        (1, 3, 1),
    ] {
        let mut rng = StdRng::seed_from_u64(11);
        let mut untouched = StdRng::seed_from_u64(11);
        let secret = NtruSecretKey::new(vec![f; N], SecretKeyDistr::UniformTernary);
        let output_key = LweSecretKey::new(
            vec![1; dimension],
            SecretKeyDistr::UniformBinary,
            params.cipher_modulus(),
        );
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                NtruLweKeySwitchingKey::generate(
                    &secret,
                    UintModulus(source_q),
                    &output_key,
                    &key_parameters,
                    &mut rng,
                );
            }))
            .is_err()
        );
        assert_eq!(rng.next_u64(), untouched.next_u64());
    }
}

// One small key serves every evaluation boundary; invalid generation preserves RNG state.
#[test]
fn validation_precedes_output_writes_and_key_sampling() {
    let modulus = BarrettModulus::new(65537u32);
    let params = LweParameters::new(
        LweDimension::new(3),
        2,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let secret = NtruSecretKey::new(
        F.iter().map(|&value| value as i32).collect(),
        SecretKeyDistr::UniformTernary,
    );
    let target = LweSecretKey::new(
        vec![1u32, 0, 1],
        SecretKeyDistr::UniformBinary,
        params.cipher_modulus(),
    );
    let basis = ApproxSignedBasis::new(Some(65537), DecompositionBaseLog::new(4), None);
    let key_parameters =
        LweKeySwitchingParameters::new(params.encryption_parameters().clone(), basis);
    let mut rng = StdRng::seed_from_u64(10);
    let key = NtruLweKeySwitchingKey::generate(
        &secret,
        NativeModulus::new(),
        &target,
        &key_parameters,
        &mut rng,
    );
    check_scalar_errors(&key);
    check_shared_input_errors(&key);
    check_bound_return_state(&key);
    check_bound_workspace_errors(&key);
    check_generation_errors(&params);
}

// Return actual encrypted coefficients to an independent, noninvertible LWE secret.
fn check_encrypted_return<T: FheUint, Q: Modulus<ValueT = T>>(
    input: &NtruCiphertext<Vec<T>>,
    secret: &NtruSecretKey<T>,
    source: Q,
) {
    let target = BarrettModulus::new(T::as_from(65537u32));
    let params = LweParameters::new(
        LweDimension::new(7),
        T::as_from(16u32),
        target,
        SecretKeyDistr::fixed_hamming_weight_binary(7, 2),
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x4e54524c57);
    let output_secret = LweSecretKey::generate(params.encryption_parameters(), &mut rng);
    let key_parameters = LweKeySwitchingParameters::new(
        params.encryption_parameters().clone(),
        ApproxSignedBasis::new(target.explicit_value(), DecompositionBaseLog::new(4), None),
    );
    let key =
        NtruLweKeySwitchingKey::generate(secret, source, &output_secret, &key_parameters, &mut rng);
    let evaluator = LweReturnEvaluator::new(&key, target);
    let mut workspace = evaluator.new_scalar_workspace();
    let mut output = LweCiphertext::zero(params.dimension().get());
    for index in [0, 31, 3, 16, 0] {
        evaluator.return_at_to(input.as_view(), index, output.as_mut_view(), &mut workspace);
        assert_eq!(
            output_secret.decrypt_message(&output, &params),
            T::as_from((3 * index + 1) % 8)
        );
    }
}

// Recover an NTT ciphertext to coefficients before exercising the common return API.
fn check_ntt_encryption<T: FheUint, Table: primus_ntt::MonomialNttTable<ValueT = T>>(q: T) {
    use primus_ntru::{NtruParameters, NttNtruSecretKey};
    use primus_poly::Polynomial;
    let modulus = BarrettModulus::new(q);
    let ntt = Table::new(PolyLength::new(32), modulus).unwrap();
    let params = NtruParameters::new(
        PolyLength::new(32),
        T::as_from(16u32),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x4e54524e54);
    let (secret, transformed) =
        NttNtruSecretKey::generate_pair(params.encryption_parameters(), &ntt, &mut rng).unwrap();
    let message = Polynomial::new(
        (0..32usize)
            .map(|i| T::as_from((3 * i + 1) % 8))
            .collect::<Vec<_>>(),
    );
    let input = transformed
        .encrypt_message(
            &message,
            &params,
            PlaintextEmbedding::Unsigned,
            &ntt,
            &mut rng,
        )
        .into_coeff_form(&ntt);
    check_encrypted_return(&input, &secret, modulus);
}

// Cover backend conversion and key independence beyond synthetic coefficient fixtures.
#[test]
fn encrypted_ntt_return_to_independent_noninvertible_lwe_secret() {
    check_ntt_encryption::<u32, primus_ntt::U32NttTable>(132_120_577);
    check_ntt_encryption::<u64, primus_ntt::U64NttTable>(1_125_899_906_826_241);
}
