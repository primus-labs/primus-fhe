use primus_integer::FheUint;
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_poly::{CrtPolynomial, Polynomial};
use primus_reduce::RingContext;

// Scatter by source degree, independently of the kernel's contiguous intervals.
fn monomial_oracle<T: FheUint + Into<u64>>(
    input: &[T],
    exponent: usize,
    n: usize,
    q: u128,
) -> Vec<T> {
    let mut output = vec![T::ZERO; input.len()];
    for (index, &value) in input.iter().enumerate() {
        let power = index % n + exponent;
        let value = u128::from(value.into());
        let value = if (power / n).is_multiple_of(2) {
            value
        } else {
            (q - value) % q
        };
        output[index / n * n + power % n] = T::as_from(value as u64);
    }
    output
}

// Check overwrite, in-place rotation, fused (X^r-1), and accumulation against
// the same independent rotation; owned outputs and mutable views share it.
fn check_single_monomial<T: FheUint + Into<u64>, M: RingContext<T>>(
    first: Polynomial<&[T]>,
    rotated: &[T],
    exponent: usize,
    q: u128,
    modulus: M,
) {
    let n = first.len();
    let mut output = Polynomial::new(vec![T::as_from(7u64); n]);
    first
        .as_view()
        .mul_monomial_to(exponent, &mut output.as_mut_view(), modulus);
    assert_eq!(output.as_ref(), rotated);

    output.copy_from(&first);
    output.mul_monomial_assign(exponent, modulus);
    assert_eq!(output.as_ref(), rotated);

    let difference: Vec<_> = rotated
        .iter()
        .zip(first.iter())
        .map(|(&a, &b)| T::as_from(((u128::from(a.into()) + q - u128::from(b.into())) % q) as u64))
        .collect();
    first.mul_monomial_sub_one_to(exponent, &mut output, modulus);
    assert_eq!(output.as_ref(), difference);

    output.copy_from(&first);
    output
        .as_mut_view()
        .add_mul_monomial_assign(&first, exponent, modulus);
    let sum: Vec<_> = rotated
        .iter()
        .zip(first.iter())
        .map(|(&a, &b)| T::as_from(((u128::from(a.into()) + u128::from(b.into())) % q) as u64))
        .collect();
    assert_eq!(output.as_ref(), sum);
}

// Scatter each source independently in Z_q[X]/(X^N+1); the implementation
// instead partitions both rotations into shared contiguous intervals.
fn check<T: FheUint + Into<u64>, M: RingContext<T>>(modulus: M, q: u128) {
    // Empty batches have no coefficients or rotation intervals to verify.
    primus_poly::add_mul_monomial_pair_assign(&mut [], &[], 0, &[], 0, 8, modulus);

    // Exhaust short rotations, then exercise longer intervals and component
    // boundaries. There is no size-dependent kernel requiring a PBS-sized N.
    for (n, components) in [(1, 1), (2, 3), (8, 1), (64, 3)] {
        let len = n * components;
        let values: Vec<T> = (0..3 * len)
            .map(|i| {
                T::as_from(match i % 5 {
                    0 => 0,
                    1 => (q - 1) as u64,
                    _ => ((i as u128 * 0x9e37_79b9_7f4a_7c15) % q) as u64,
                })
            })
            .collect();
        let first = Polynomial(&values[..len]);
        let second = Polynomial(&values[len..2 * len]);
        let exponents: Vec<_> = if n <= 8 {
            (0..2 * n).collect()
        } else {
            vec![0, 1, n / 2, n - 1, n, n + 1, n + n / 2, 2 * n - 1]
        };
        let moduli = vec![modulus; components];
        for &ra in &exponents {
            let rotated = monomial_oracle(first.as_ref(), ra, n, q);
            let mut actual = CrtPolynomial::new(first.as_ref().to_vec());
            // CRT traversal must apply the same exponent to every component.
            actual.as_mut_view().mul_monomial_assign(ra, n, &moduli);
            assert_eq!(actual.as_ref(), rotated);

            if components == 1 {
                check_single_monomial(first.as_view(), &rotated, ra, q, modulus);
            }
            for &rb in &exponents {
                let mut output = values[2 * len..].to_vec();
                // Repeat on the initialized accumulator to exercise scratch reuse.
                for _ in 0..2 {
                    let mut expected = output.clone();
                    for (source, r) in [(first.as_ref(), ra), (second.as_ref(), rb)] {
                        for (i, &value) in source.iter().enumerate() {
                            let power = i % n + r;
                            let index = i / n * n + power % n;
                            let old = u128::from(expected[index].into());
                            let value = u128::from(value.into());
                            let result = if (power / n).is_multiple_of(2) {
                                (old + value) % q
                            } else {
                                (old + q - value) % q
                            };
                            expected[index] = T::as_from(result as u64);
                        }
                    }
                    if components == 1 {
                        Polynomial(output.as_mut_slice())
                            .add_mul_monomial_pair_assign(&first, ra, &second, rb, modulus);
                    } else {
                        primus_poly::add_mul_monomial_pair_assign(
                            &mut output,
                            first.as_ref(),
                            ra,
                            second.as_ref(),
                            rb,
                            n,
                            modulus,
                        );
                    }
                    assert_eq!(
                        output, expected,
                        "N={n}, components={components}, ra={ra}, rb={rb}"
                    );
                }
            }
        }
    }
}

#[test]
fn monomial_operations_match_independent_ring_arithmetic() {
    check::<u32, _>(NativeModulus::new(), 1u128 << 32);
    check::<u64, _>(NativeModulus::new(), 1u128 << 64);
    check::<u32, _>(PowOf2Modulus::new(1u32 << 24), 1u128 << 24);
    check::<u64, _>(PowOf2Modulus::new(1u64 << 48), 1u128 << 48);
    check::<u32, _>(BarrettModulus::new(132_120_577u32), 132_120_577);
    const Q64: u64 = 1_152_921_504_606_830_593;
    check::<u64, _>(BarrettModulus::new(Q64), Q64.into());
}

// Start at both ends of the redundant range, then retain it across paired and
// odd-tail updates. The independent scatter oracle always computes in Z_q.
fn check_lazy_monomials<T: FheUint + Into<u64>>(q: T) {
    use primus_poly::{lazy_add_mul_monomial_assign, lazy_add_mul_monomial_pair_assign};
    use primus_reduce::ReduceOnceSlice;

    let modulus = BarrettModulus::new(q);
    let wide_q = u128::from(q.into());
    lazy_add_mul_monomial_pair_assign(&mut [], &[], 0, &[], 0, 32, modulus);
    lazy_add_mul_monomial_assign(&mut [], &[], 0, 32, modulus);
    for (n, components) in [(1, 1), (2, 3), (32, 3)] {
        let len = n * components;
        let first: Vec<T> = (0..len)
            .map(|i| {
                T::as_from(if i % 3 == 0 {
                    0
                } else {
                    wide_q - 1 - i as u128 % 13
                })
            })
            .collect();
        let second: Vec<T> = first.iter().copied().rev().collect();
        for a in [0, n / 2, n - 1, n, 2 * n - 1] {
            for b in [0, n / 2, n - 1, n, 2 * n - 1] {
                let mut actual: Vec<T> = (0..len)
                    .map(|i| T::as_from([0, wide_q - 1, wide_q, 2 * wide_q - 1][i % 4]))
                    .collect();
                let mut expected: Vec<_> = actual
                    .iter()
                    .map(|&v| u128::from(v.into()) % wide_q)
                    .collect();
                let rotations = [
                    monomial_oracle(&first, a, n, wide_q),
                    monomial_oracle(&second, b, n, wide_q),
                    monomial_oracle(&first, b, n, wide_q),
                ];
                for _ in 0..2 {
                    lazy_add_mul_monomial_pair_assign(
                        &mut actual,
                        &first,
                        a,
                        &second,
                        b,
                        n,
                        modulus,
                    );
                    assert!(actual.iter().all(|&v| v < q + q));
                    lazy_add_mul_monomial_assign(&mut actual, &first, b, n, modulus);
                    assert!(actual.iter().all(|&v| v < q + q));
                    for rotated in &rotations {
                        for (sum, &value) in expected.iter_mut().zip(rotated) {
                            *sum = (*sum + u128::from(value.into())) % wide_q;
                        }
                    }
                }
                modulus.reduce_once_slice_assign(&mut actual);
                assert!(
                    actual
                        .iter()
                        .zip(expected)
                        .all(|(&a, b)| u128::from(a.into()) == b),
                    "n={n}, a={a}, b={b}"
                );
            }
        }
    }
}

#[test]
fn lazy_monomials_preserve_residue_and_spare_bit_bounds() {
    check_lazy_monomials(132_120_577u32);
    check_lazy_monomials((1u32 << 30) - 35);
    check_lazy_monomials(1_125_899_906_826_241u64);
    check_lazy_monomials((1u64 << 62) - 57);
}
