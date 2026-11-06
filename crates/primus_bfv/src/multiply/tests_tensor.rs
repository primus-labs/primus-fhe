//! Exact BFV tensor/scaling semantics, independent of production CRT and NTT.

use super::reference::BfvReferenceMultiplier;
use crate::{BfvCiphertext, BfvContext, BfvMultiplier, BfvParameters, BfvQuadraticCiphertext};
use dashu_int::IBig;
use primus_data::{Data, DataMut};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Exact, unscaled integer BFV tensor represented in the computation basis QP.
///
/// Each of the three components occupies `(cipher_moduli.len() +
/// auxiliary_moduli.len()) * N` entries, with Q limbs followed by P limbs, in
/// modulus-major NTT order. The mathematical coefficients are the integer
/// negacyclic products of centered Q representatives, before reduction or
/// scaling. The complete product QP is greater than NQ², so it distinguishes
/// every coefficient of one tensor. Only its owning compatible multiplier may
/// overwrite or scale this storage; arbitrary accumulation would require a
/// stronger coefficient bound.
///
/// This is a computation artifact, not a ciphertext under an enlarged secret
/// modulus. In particular it cannot be supplied to relinearization or recovery.
#[derive(Clone, Debug)]
struct BfvRawTensor {
    data: Vec<u64>,
    n: usize,
    level: usize,
    t: u64,
    q: Vec<u64>,
    p: Vec<u64>,
}

impl BfvRawTensor {
    /// Returns the full secret/ciphertext ring dimension N.
    #[must_use]
    fn poly_length(&self) -> usize {
        self.n
    }

    /// Returns the bound ciphertext level.
    #[must_use]
    fn level(&self) -> usize {
        self.level
    }

    /// Returns the plaintext modulus used for subsequent scaling.
    #[must_use]
    fn plain_modulus(&self) -> u64 {
        self.t
    }

    /// Borrows the ordered ciphertext basis.
    #[must_use]
    fn cipher_moduli(&self) -> &[u64] {
        &self.q
    }

    /// Borrows the ordered computation-only auxiliary basis.
    #[must_use]
    fn auxiliary_moduli(&self) -> &[u64] {
        &self.p
    }

    /// Returns the complete QP polynomial length of one component.
    #[must_use]
    fn rns_poly_len(&self) -> usize {
        self.data.len() / 3
    }
}

impl AsRef<[u64]> for BfvRawTensor {
    fn as_ref(&self) -> &[u64] {
        &self.data
    }
}

impl BfvMultiplier<'_> {
    /// Allocates zeroed raw tensor storage with this multiplier's numeric binding.
    #[must_use]
    fn new_raw_tensor(&self) -> BfvRawTensor {
        BfvRawTensor {
            data: vec![0; self.raw.len()],
            n: self.context.parameters().poly_length().get(),
            level: self.level,
            t: self.context.codec(self.level).t(),
            q: self
                .context
                .codec(self.level)
                .base_q()
                .moduli_values()
                .to_vec(),
            p: self.auxiliary_moduli().to_vec(),
        }
    }

    /// Writes the exact unscaled tensor of centered component lifts in QP.
    ///
    /// # Panics
    /// Rejects either complete input length or any raw-output metadata mismatch
    /// before writing output or scratch.
    fn mul_raw_to<A, B>(
        &mut self,
        lhs: &BfvCiphertext<A>,
        rhs: &BfvCiphertext<B>,
        output: &mut BfvRawTensor,
    ) where
        A: Data<Elem = u64>,
        B: Data<Elem = u64>,
    {
        self.validate_input(lhs.as_ref());
        self.validate_input(rhs.as_ref());
        self.validate_raw(output);
        self.workspace.tensor(
            self.context,
            self.level,
            &self.lift,
            lhs.as_ref(),
            rhs.as_ref(),
            false,
            &mut output.data,
        );
    }

    /// Writes the exact raw square, reusing one set of lifted input transforms.
    ///
    /// Inherits [`Self::mul_raw_to`]'s representation and prewrite checks.
    fn square_raw_to<A>(&mut self, input: &BfvCiphertext<A>, output: &mut BfvRawTensor)
    where
        A: Data<Elem = u64>,
    {
        self.validate_input(input.as_ref());
        self.validate_raw(output);
        self.workspace.tensor(
            self.context,
            self.level,
            &self.lift,
            input.as_ref(),
            input.as_ref(),
            true,
            &mut output.data,
        );
    }

    /// Scales each complete raw component as `round(t*z/Q) mod Q`.
    ///
    /// Q is odd, so an integer `t*z` cannot be exactly halfway between multiples
    /// of Q. Nearest rounding therefore has no tie ambiguity, including for
    /// negative z. The result uses the original Q basis and NTT convention.
    ///
    /// # Panics
    /// Rejects raw metadata or the complete quadratic-output length before any
    /// output or scratch writes.
    fn scale_and_round_to<C>(
        &mut self,
        input: &BfvRawTensor,
        output: &mut BfvQuadraticCiphertext<C>,
    ) where
        C: DataMut<Elem = u64>,
    {
        self.validate_raw(input);
        self.validate_output(output.as_ref());
        // Preserve the test's NTT tensor for its independent component oracle.
        // Production consumes its own tensor in place; this test reuses that
        // existing allocation rather than adding a production-only copy buffer.
        self.raw.copy_from_slice(input.as_ref());
        self.workspace.scale(
            self.context,
            self.level,
            &self.lift,
            &mut self.raw,
            output.as_mut(),
        );
    }

    fn validate_raw(&self, raw: &BfvRawTensor) {
        assert_eq!(raw.n, self.context.parameters().poly_length().get());
        assert_eq!(raw.level, self.level);
        assert_eq!(raw.t, self.context.codec(self.level).t());
        assert_eq!(
            raw.q,
            self.context.codec(self.level).base_q().moduli_values()
        );
        assert_eq!(raw.p, self.auxiliary_moduli());
        assert_eq!(raw.data.len(), self.raw.len());
    }
}

const N: usize = 32;
const Q: [u64; 3] = [
    1_125_899_906_826_241,
    1_125_899_906_629_633,
    1_125_899_906_248_961,
];
// Independently checked primes, all 1 modulo 2N. P exceeds N*Q even at
// level zero; it is computation-only and is never a ciphertext modulus.
const P: [u64; 4] = [
    1_125_899_905_562_561,
    1_125_899_905_560_257,
    1_125_899_905_560_193,
    1_125_899_905_559_041,
];

fn context(t: u64) -> BfvContext {
    BfvContext::try_with_levels(
        BfvParameters::try_with_error_distribution(
            PolyLength::new(N),
            BarrettModulus::new(t),
            BarrettModulus::new(2_199_023_190_017),
            &Q.map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
        3,
    )
    .unwrap()
}

fn product(moduli: &[u64]) -> IBig {
    moduli.iter().fold(IBig::ONE, |value, &q| value * q)
}

fn canonical(value: &IBig, modulus: &IBig) -> IBig {
    let remainder = value % modulus;
    if remainder < IBig::ZERO {
        remainder + modulus
    } else {
        remainder
    }
}

fn residue(value: &IBig, modulus: u64) -> u64 {
    u64::try_from(canonical(value, &IBig::from(modulus))).unwrap()
}

fn multiply(a: u64, b: u64, q: u64) -> u64 {
    (u128::from(a) * u128::from(b) % u128::from(q)) as u64
}

fn power(mut value: u64, mut exponent: u64, q: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, value, q);
        }
        value = multiply(value, value, q);
        exponent >>= 1;
    }
    result
}

fn evaluation_points(q: u64) -> Vec<u64> {
    // Derive the backend's documented smallest-root/bit-reversed convention
    // directly in the finite field, without reading its tables or transforms.
    let witness = (2..)
        .map(|candidate| power(candidate, (q - 1) / (2 * N) as u64, q))
        .find(|&root| power(root, N as u64, q) == q - 1)
        .unwrap();
    let root = (0..N)
        .map(|i| power(witness, (2 * i + 1) as u64, q))
        .min()
        .unwrap();
    (0usize..N)
        .map(|index| {
            let reverse = index.reverse_bits() >> (usize::BITS - N.ilog2());
            power(root, (2 * reverse + 1) as u64, q)
        })
        .collect()
}

fn dft(coefficients: &[IBig], q: u64) -> Vec<u64> {
    let reduced: Vec<_> = coefficients.iter().map(|x| residue(x, q)).collect();
    evaluation_points(q)
        .iter()
        .map(|&point| {
            reduced
                .iter()
                .rev()
                .fold(0, |sum, &x| (multiply(sum, point, q) + x) % q)
        })
        .collect()
}

fn inverse_dft(values: &[u64], q: u64) -> Vec<u64> {
    let points = evaluation_points(q);
    let inverse_n = power(N as u64, q - 2, q);
    (0..N)
        .map(|degree| {
            let sum = values.iter().zip(&points).fold(0, |sum, (&x, &point)| {
                (sum + multiply(x, power(point, q - 1 - degree as u64, q), q)) % q
            });
            multiply(sum, inverse_n, q)
        })
        .collect()
}

fn negacyclic(lhs: &[IBig], rhs: &[IBig]) -> Vec<IBig> {
    let mut output = vec![IBig::ZERO; N];
    for (i, left) in lhs.iter().enumerate() {
        for (j, right) in rhs.iter().enumerate() {
            if i + j < N {
                output[i + j] += left * right;
            } else {
                output[i + j - N] -= left * right;
            }
        }
    }
    output
}

fn add(lhs: &[IBig], rhs: &[IBig]) -> Vec<IBig> {
    lhs.iter().zip(rhs).map(|(a, b)| a + b).collect()
}

fn tensor(lhs: &[Vec<IBig>; 2], rhs: &[Vec<IBig>; 2]) -> [Vec<IBig>; 3] {
    [
        negacyclic(&lhs[0], &rhs[0]),
        add(&negacyclic(&lhs[0], &rhs[1]), &negacyclic(&lhs[1], &rhs[0])),
        negacyclic(&lhs[1], &rhs[1]),
    ]
}

fn nearest(numerator: &IBig, denominator: &IBig) -> IBig {
    // Odd Q makes true half ties impossible for integer t*T. Work in signed
    // arbitrary precision so negative near-half values cannot floor wrongly.
    if numerator < &IBig::ZERO {
        -nearest(&-numerator, denominator)
    } else {
        (numerator * 2u64 + denominator) / (denominator * 2u64)
    }
}

fn scaled(raw: &[Vec<IBig>; 3], t: u64, q: &IBig) -> [Vec<IBig>; 3] {
    raw.each_ref()
        .map(|component| component.iter().map(|x| nearest(&(x * t), q)).collect())
}

fn ciphertext(components: &[Vec<IBig>; 2], moduli: &[u64]) -> BfvCiphertext<Vec<u64>> {
    BfvCiphertext::from_raw(
        components
            .iter()
            .flat_map(|component| moduli.iter().flat_map(|&q| dft(component, q)))
            .collect::<Vec<_>>(),
    )
}

fn verify_components(actual: &[u64], expected: &[Vec<IBig>; 3], moduli: &[u64]) {
    assert_eq!(actual.len(), 3 * N * moduli.len());
    for (actual, expected) in actual.chunks_exact(N * moduli.len()).zip(expected) {
        for (actual_limb, &q) in actual.as_chunks::<N>().0.iter().zip(moduli) {
            assert_eq!(actual_limb.as_slice(), dft(expected, q));
        }
    }
}

fn compose_centered_component(actual: &[u64], moduli: &[u64]) -> Vec<IBig> {
    let limbs: Vec<_> = actual
        .as_chunks::<N>()
        .0
        .iter()
        .zip(moduli)
        .map(|(values, &q)| inverse_dft(values, q))
        .collect();
    let modulus = product(moduli);
    (0..N)
        .map(|degree| {
            // Textbook CRT sum with finite-field inverses; no production
            // compose, base converter or fixed-width integer is used.
            let mut sum = IBig::ZERO;
            for (limb, &q) in limbs.iter().zip(moduli) {
                let punctured = &modulus / q;
                let inverse = power(residue(&punctured, q), q - 2, q);
                sum += punctured * multiply(limb[degree], inverse, q);
            }
            let x = canonical(&sum, &modulus);
            if &x * 2u64 > modulus { x - &modulus } else { x }
        })
        .collect()
}

fn verify_phase(
    actual: &BfvQuadraticCiphertext<Vec<u64>>,
    expected: &[Vec<IBig>; 3],
    moduli: &[u64],
) {
    let secret: Vec<_> = (0..N).map(|i| IBig::from([-1, 1, 0, 1][i % 4])).collect();
    let expected_phase = add(
        &add(&expected[0], &negacyclic(&expected[1], &secret)),
        &negacyclic(&expected[2], &negacyclic(&secret, &secret)),
    );
    let length = N * moduli.len();
    for (limb, &q) in moduli.iter().enumerate() {
        let s = dft(&secret, q);
        let phase = dft(&expected_phase, q);
        for index in 0..N {
            let c0 = actual.as_ref()[limb * N + index];
            let c1 = actual.as_ref()[length + limb * N + index];
            let c2 = actual.as_ref()[2 * length + limb * N + index];
            assert_eq!(
                (c0 + multiply(c1, s[index], q) + multiply(c2, multiply(s[index], s[index], q), q))
                    % q,
                phase[index]
            );
        }
    }
}

#[test]
fn dense_monomial_and_square_products_match_exact_integer_tensor_at_all_levels() {
    assert!(product(&Q) > IBig::from(u128::MAX));
    for t in [2, 193] {
        let context = context(t);
        for level in 0..context.level_count() {
            let moduli = &Q[..Q.len() - level];
            let q = product(moduli);
            let half = &q / 2u64;
            let mut multiplier = BfvMultiplier::try_new(&context, level, &P).unwrap();
            let mut reference = BfvReferenceMultiplier::new(&context, level);
            let mut raw = multiplier.new_raw_tensor();
            assert_eq!(raw.poly_length(), N);
            assert_eq!(raw.level(), level);
            assert_eq!(raw.plain_modulus(), t);
            assert_eq!(raw.cipher_moduli(), moduli);
            assert_eq!(raw.auxiliary_moduli(), P);
            let extended: Vec<_> = moduli.iter().chain(&P).copied().collect();
            assert_eq!(raw.rns_poly_len(), N * extended.len());
            let mut output = context.new_quadratic_ciphertext(level);
            let mut reference_output = context.new_quadratic_ciphertext(level);
            for family in 0..3 {
                let monomial = family == 1;
                let lhs: [Vec<IBig>; 2] = std::array::from_fn(|component| {
                    (0..N)
                        .map(|i| {
                            if family == 2 {
                                half.clone()
                            } else if monomial && i != N - 1 - component {
                                IBig::ZERO
                            } else if monomial || (i + component) % 3 == 0 {
                                -&half + IBig::from(i)
                            } else {
                                &half - IBig::from(i + component)
                            }
                        })
                        .collect()
                });
                let rhs: [Vec<IBig>; 2] = std::array::from_fn(|component| {
                    (0..N)
                        .map(|i| {
                            if family == 2 {
                                half.clone()
                            } else if monomial && i != 2 + component {
                                IBig::ZERO
                            } else if (i + component) % 2 == 0 {
                                &half - IBig::from(i + 3)
                            } else {
                                -&half + IBig::from(i + 5)
                            }
                        })
                        .collect()
                });
                let left = ciphertext(&lhs, moduli);
                let right = ciphertext(&rhs, moduli);
                let expected_raw = tensor(&lhs, &rhs);
                // The shared coefficient buffer and consumed raw tensor must
                // not depend on initialization or the preceding request.
                multiplier.workspace.coefficients.fill(u64::MAX);
                multiplier.workspace.lhs_p.fill(u64::MAX);
                multiplier.workspace.rhs_p.fill(u64::MAX);
                multiplier.raw.fill(u64::MAX);
                multiplier.mul_raw_to(&left.as_view(), &right.as_view(), &mut raw);
                verify_components(raw.as_ref(), &expected_raw, &extended);
                // Exercise actual 300-bit recovery, rather than checking only
                // residues whose u128 truncation could accidentally agree.
                for (actual, expected) in raw
                    .as_ref()
                    .chunks_exact(raw.rns_poly_len())
                    .zip(&expected_raw)
                {
                    assert_eq!(compose_centered_component(actual, &extended), *expected);
                }
                let expected = scaled(&expected_raw, t, &q);
                multiplier.scale_and_round_to(&raw, &mut output.as_mut_view());
                verify_components(output.as_ref(), &expected, moduli);
                verify_phase(&output, &expected, moduli);
                reference.multiply_to(&left, &right, &mut reference_output);
                assert_eq!(output.as_ref(), reference_output.as_ref());
                multiplier.multiply_to(&left, &right, &mut reference_output);
                assert_eq!(output.as_ref(), reference_output.as_ref());

                multiplier.square_raw_to(&left, &mut raw);
                let expected_square_raw = tensor(&lhs, &lhs);
                verify_components(raw.as_ref(), &expected_square_raw, &extended);
                let expected_square = scaled(&expected_square_raw, t, &q);
                multiplier.square_to(&left, &mut output);
                verify_components(output.as_ref(), &expected_square, moduli);
                reference.square_to(&left, &mut reference_output);
                assert_eq!(output.as_ref(), reference_output.as_ref());
                multiplier.multiply_to(&left, &left, &mut reference_output);
                assert_eq!(output.as_ref(), reference_output.as_ref());
            }
        }
    }
}

#[test]
fn negative_half_neighbors_cross_sum_and_standard_scale_have_distinct_oracles() {
    let t = 193;
    let context = context(t);
    for level in 0..context.level_count() {
        let moduli = &Q[..Q.len() - level];
        let q = product(moduli);
        let delta = &q / t;
        let near_half = &q / (2 * t);
        let near_quarter = (&q / (4 * t)) + IBig::ONE;
        let mut fixtures = vec![
            -&near_half - IBig::ONE,
            -&near_half,
            near_half.clone(),
            &near_half + IBig::ONE,
            -&near_quarter,
            near_quarter.clone(),
            &delta / 2u64,
            -(&delta / 2u64),
        ];
        // Solve t*x = (Q±1)/2 (mod Q), so the rational is only 1/(2Q)
        // away from a half. At 150 bits f64 cannot distinguish the sides.
        for above in [false, true] {
            let target = (&q - IBig::ONE) / 2u64 + u64::from(above);
            let k = multiply((t - (&target % t)) % t, power(residue(&q, t), t - 2, t), t);
            let x = (&target + &q * k) / t;
            let x = if &x * 2u64 > q { x - &q } else { x };
            assert_eq!(canonical(&(&x * t), &q), target);
            fixtures.push(x.clone());
            fixtures.push(-x);
        }
        let lhs: [Vec<IBig>; 2] = std::array::from_fn(|_| {
            (0..N)
                .map(|i| fixtures[i % fixtures.len()].clone())
                .collect()
        });
        let mut unit = vec![IBig::ZERO; N];
        unit[0] = IBig::ONE;
        let rhs = [unit.clone(), unit];
        let left = ciphertext(&lhs, moduli);
        let right = ciphertext(&rhs, moduli);
        let expected_raw = tensor(&lhs, &rhs);
        let expected = scaled(&expected_raw, t, &q);
        assert_eq!(expected[0][0], -IBig::ONE);
        assert_eq!(expected[0][1], IBig::ZERO);
        assert_eq!(expected[0][2], IBig::ZERO);
        assert_eq!(expected[0][3], IBig::ONE);
        // Each quarter-scale term rounds to zero; their merged c1 is one.
        assert_eq!(expected[0][5], IBig::ZERO);
        assert_eq!(expected[1][5], IBig::ONE);
        // For an even Delta the exact Delta/2 tie would round up under 1/Delta,
        // whereas t*(Delta/2)/Q is strictly below half and must round to zero.
        if &delta % 2u64 == 0 {
            assert_eq!(expected[0][6], IBig::ZERO);
            assert_eq!(nearest(&fixtures[6], &delta), IBig::ONE);
        }
        let mut multiplier = BfvMultiplier::try_new(&context, level, &P).unwrap();
        let mut reference = BfvReferenceMultiplier::new(&context, level);
        let mut output = context.new_quadratic_ciphertext(level);
        multiplier.multiply_to(&left, &right, &mut output);
        verify_components(output.as_ref(), &expected, moduli);
        reference.multiply_to(&left, &right, &mut output);
        verify_components(output.as_ref(), &expected, moduli);
    }
}

#[test]
fn insufficient_lift_and_malformed_or_foreign_storage_are_rejected_before_writes() {
    let context = context(193);
    for level in 0..context.level_count() {
        // A 50-bit P is insufficient even for the one-prime 50-bit Q level:
        // dense cross products need P>N*Q, not merely one extra NTT prime.
        assert!(BfvMultiplier::try_new(&context, level, &P[..1]).is_err());
        assert!(BfvMultiplier::try_new(&context, level, &[]).is_err());
        assert!(BfvMultiplier::try_new(&context, level, &[Q[0]]).is_err());
        let mut multiplier = BfvMultiplier::try_new(&context, level, &P).unwrap();
        let input = context.new_ciphertext(level);
        let mut raw = multiplier.new_raw_tensor();
        let before = raw.as_ref().to_vec();
        for length in [0, input.as_ref().len() - 1, input.as_ref().len() + 1] {
            let malformed = BfvCiphertext::zero_raw(length);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    multiplier.mul_raw_to(&malformed, &input, &mut raw);
                }))
                .is_err()
            );
            assert_eq!(raw.as_ref(), before);
        }
        let mut output =
            BfvQuadraticCiphertext::from_raw(vec![17; 3 * context.rns_poly_len(level)]);
        let before = output.clone();
        let other_context = self::context(2);
        let other = BfvMultiplier::try_new(&other_context, level, &P).unwrap();
        let foreign_raw = other.new_raw_tensor();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                multiplier.scale_and_round_to(&foreign_raw, &mut output);
            }))
            .is_err()
        );
        assert_eq!(output, before);
        let mut malformed_output =
            BfvQuadraticCiphertext::from_raw(vec![17; output.as_ref().len() - 1]);
        let before = malformed_output.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                multiplier.scale_and_round_to(&raw, &mut malformed_output);
            }))
            .is_err()
        );
        assert_eq!(malformed_output, before);
    }
    assert!(BfvMultiplier::try_new(&context, usize::MAX, &P).is_err());
}

#[test]
fn automatic_basis_is_disjoint_and_exact_at_every_level() {
    let context = context(193);
    for level in 0..context.level_count() {
        let moduli = &Q[..Q.len() - level];
        let mut automatic = BfvMultiplier::try_with_default_basis(&context, level).unwrap();
        let auxiliary = automatic.auxiliary_moduli();
        assert!(product(auxiliary) > product(moduli) * N);
        for (i, &p) in auxiliary.iter().enumerate() {
            assert!((1 << 59..1 << 60).contains(&p));
            assert_eq!(p % (2 * N) as u64, 1);
            assert!(!moduli.contains(&p));
            assert!(!auxiliary[..i].contains(&p));
        }
        let half = product(moduli) / 2u64;
        let inputs: [Vec<IBig>; 2] = std::array::from_fn(|component| {
            (0..N)
                .map(|i| {
                    if (i + component) % 2 == 0 {
                        &half - i
                    } else {
                        -&half + i
                    }
                })
                .collect()
        });
        let encrypted = ciphertext(&inputs, moduli);
        let expected = scaled(&tensor(&inputs, &inputs), 193, &product(moduli));
        let mut output = context.new_quadratic_ciphertext(level);
        automatic.square_to(&encrypted, &mut output);
        verify_components(output.as_ref(), &expected, moduli);
    }
    assert!(BfvMultiplier::try_with_default_basis(&context, usize::MAX).is_err());
}

#[test]
fn prime_selection_rejects_strong_pseudoprimes() {
    for n in 0u64..4096 {
        let trial_division = n >= 2
            && !(2..)
                .take_while(|d| d * d <= n)
                .any(|d| n.is_multiple_of(d));
        assert_eq!(super::is_prime(n), trial_division, "n={n}");
    }
    for composite in [341_550_071_728_321, 3_825_123_056_546_413_051] {
        assert!(!super::is_prime(composite));
    }
    for prime in Q.into_iter().chain(P).chain([2_305_843_009_213_693_951]) {
        assert!(super::is_prime(prime));
    }
}
