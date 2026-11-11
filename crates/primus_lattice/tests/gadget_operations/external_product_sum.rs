//! Fused NLEV sums: independent polynomial oracle, exact NTT differential,
//! Fourier torus error, empty sums, pair counts and dirty workspace reuse.

use primus_decompose::DecompositionBaseLog;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_lattice::{
    nlev::{FourierNlev, FourierNlevOwned, Nlev, NttNlev},
    ntru::Ntru,
    workspace::{FourierNtruExternalProductWorkspace, NttNtruExternalProductWorkspace},
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, U32NttTable, U64NttTable};
use primus_poly::{Polynomial, PolynomialIter};
use primus_reduce::{Reduce, RingContext};
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::{N, POLY_LENGTH, noiseless_nlev};

// Noiseless f=1 gadgets and the independent plaintext polynomial operands.
struct SumFixture<T: FheUint> {
    gadgets: Vec<Nlev<Vec<T>>>,
    inputs: Vec<Polynomial<Vec<T>>>,
    messages: Vec<Polynomial<Vec<T>>>,
}

// With f=1 a noiseless NLEV is just its message multiplied by every gadget
// weight. Dense small signed messages force all terms and negacyclic wrapping
// to contribute, rather than reducing the sum to a one-hot copy.
fn fixture<T: FheUint, M: RingContext<T>>(
    basis: &ApproxSignedBasis<T>,
    modulus: M,
    input: Vec<T>,
) -> SumFixture<T> {
    let inputs: Vec<_> = PolynomialIter::new(&input, N)
        .map(|p| Polynomial::new(p.as_ref().to_vec()))
        .collect();
    let messages: Vec<_> = (0..inputs.len())
        .map(|j| {
            Polynomial::new(
                (0..N)
                    .map(|i| {
                        let small = T::as_from((i * 3 + j) % 5);
                        if (i + j) % 2 == 0 {
                            small
                        } else {
                            modulus.reduce_neg(small)
                        }
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    let gadgets = messages
        .iter()
        .map(|message| noiseless_nlev(message, basis, modulus))
        .collect();
    SumFixture {
        gadgets,
        inputs,
        messages,
    }
}

// Coefficient-domain convolution provides an oracle independent of decomposition
// and transforms; the separate-product differential alone would share both.
fn expected_sum<T: FheUint, M: RingContext<T>>(
    inputs: &[Polynomial<Vec<T>>],
    messages: &[Polynomial<Vec<T>>],
    modulus: M,
) -> Polynomial<Vec<T>> {
    let mut sum = Polynomial::zero(N);
    let mut product = Polynomial::<Vec<T>>::zero(N);
    for (input, message) in inputs.iter().zip(messages) {
        input.naive_mul_to(message, &mut product, modulus);
        sum.add_assign(&product, modulus);
    }
    sum
}

/// Fixed shape errors leave output untouched. In Fourier, even late failures
/// leave output untouched because the partial sum lives in scratch.
fn check_sum_shapes<T: FheUint, G: Clone>(
    gadgets: [G; 2],
    short_gadget: G,
    inputs: &[Polynomial<Vec<T>>],
    output: &mut Ntru<Vec<T>>,
    preserve_output_on_late_failure: bool,
    mut sum: impl FnMut(&[G], &[Polynomial<&[T]>], Ntru<&mut [T]>),
) {
    let inputs = [inputs[0].as_view(), inputs[1].as_view()];
    let short_input = [
        inputs[0].as_view(),
        Polynomial::new(&inputs[1].as_ref()[..N - 1]),
    ];
    let short_gadgets = [gadgets[0].clone(), short_gadget];
    for (gadgets, inputs, output_len, late) in [
        (&gadgets[..], &inputs[..1], N, false),
        (&gadgets[..1], &inputs[..], N, false),
        (&gadgets[..], &inputs[..], N - 1, false),
        (&gadgets[..], &short_input[..], N, true),
        (&short_gadgets[..], &inputs[..], N, true),
    ] {
        output.as_mut().fill(T::ONE);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                sum(
                    gadgets,
                    inputs,
                    Ntru::new(&mut output.as_mut()[..output_len]),
                );
            }))
            .is_err()
        );
        if !late || preserve_output_on_late_failure {
            assert!(output.as_ref().iter().all(|&x| x == T::ONE));
        }
    }
}

// Full decomposition gives an exact convolution oracle. Boundary failures run
// first, so the following nonempty/empty sums also verify workspace recovery.
fn ntt<T: FheUint, Table: NttTable<ValueT = T>>(q: T, table: Table) {
    let modulus = BarrettModulus::new(q);
    // Both primes have bit widths divisible by three: no bits are dropped,
    // so the independent polynomial oracle is exact.
    let basis = ApproxSignedBasis::new(Some(q), DecompositionBaseLog::new(3), None);
    let values = (0..3 * N)
        .map(|i| modulus.reduce(T::as_from(i * 997 + 1)))
        .collect();
    let SumFixture {
        gadgets,
        inputs,
        messages,
    } = fixture(&basis, modulus, values);
    let gadgets: Vec<_> = gadgets
        .into_iter()
        .map(|g| g.into_ntt_form(&table))
        .collect();
    let mut workspace = NttNtruExternalProductWorkspace::new(POLY_LENGTH);
    let mut output = Ntru::new(vec![T::MAX; N]);
    let gadget_len = gadgets[1].as_ref().len();
    check_sum_shapes(
        [gadgets[0].as_view(), gadgets[1].as_view()],
        NttNlev::new(&gadgets[1].as_ref()[..gadget_len - 1]),
        &inputs,
        &mut output,
        false,
        |gadgets, inputs, output| {
            NttNlev::external_product_sum_to(
                gadgets,
                inputs,
                output,
                &basis,
                modulus,
                &table,
                &mut workspace,
            );
        },
    );

    // A valid call after late failures overwrites all stale transform state.
    for count in [3, 1, 0] {
        NttNlev::external_product_sum_to(
            &gadgets[..count],
            &inputs[..count],
            output.as_mut_view(),
            &basis,
            modulus,
            &table,
            &mut workspace,
        );
        let mut separate = Ntru::<Vec<T>>::zero(N);
        let mut product = Ntru::<Vec<T>>::zero(N);
        for (gadget, input) in gadgets[..count].iter().zip(&inputs[..count]) {
            gadget.external_product_to(
                input,
                &mut product,
                &basis,
                modulus,
                &table,
                &mut workspace,
            );
            separate.add_assign(&product, modulus);
        }
        assert_eq!(output.as_ref(), separate.as_ref());
        assert_eq!(
            output.as_ref(),
            expected_sum(&inputs[..count], &messages[..count], modulus).as_ref()
        );
    }
}

#[test]
fn ntt_sum_matches_separate_products_and_polynomial_oracle() {
    ntt(
        257u32,
        U32NttTable::new(POLY_LENGTH, BarrettModulus::new(257u32)).unwrap(),
    );
    ntt(
        998_244_353u64,
        U64NttTable::new(POLY_LENGTH, BarrettModulus::new(998_244_353u64)).unwrap(),
    );
}

// The independent integer convolution is the phase oracle for f=1. u64 includes
// low bits that FFT cannot represent exactly; allow an absolute torus error of
// 2^-42 (one unit for u32), not bitwise equality with separately rounded products.
pub(super) fn check_fourier<T: TorusFftValue, Table: FftTable>(table: &Table) {
    let modulus = NativeModulus::<T>::new();
    let basis = ApproxSignedBasis::new(None, DecompositionBaseLog::new(8), None);
    let mut fft = FftEngine::new(table);
    let values = (0..3 * N)
        .map(|i| T::as_from((i as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15)))
        .collect();
    let SumFixture {
        gadgets,
        inputs,
        messages,
    } = fixture(&basis, modulus, values);
    let gadgets: Vec<_> = gadgets
        .iter()
        .map(|g| {
            let mut transformed = FourierNlevOwned::zero(basis.level_count().get() * N / 2);
            g.write_fourier_form(&mut transformed, &mut fft);
            transformed
        })
        .collect();
    let mut workspace = FourierNtruExternalProductWorkspace::new(POLY_LENGTH);
    let mut output = Ntru::new(vec![T::MAX; N]);
    let tolerance = T::ONE << T::BITS.saturating_sub(42);
    let gadget_len = gadgets[1].as_ref().len();
    check_sum_shapes(
        [gadgets[0].as_view(), gadgets[1].as_view()],
        FourierNlev::new(&gadgets[1].as_ref()[..gadget_len - 1]),
        &inputs,
        &mut output,
        true,
        |gadgets, inputs, output| {
            FourierNlev::external_product_sum_to(
                gadgets,
                inputs,
                output,
                &basis,
                &mut fft,
                &mut workspace,
            );
        },
    );

    // A valid call after late failures overwrites all stale transform state.
    for count in [3, 1, 0] {
        FourierNlev::external_product_sum_to(
            &gadgets[..count],
            &inputs[..count],
            output.as_mut_view(),
            &basis,
            &mut fft,
            &mut workspace,
        );
        let mut separate = Ntru::<Vec<T>>::zero(N);
        let mut product = Ntru::<Vec<T>>::zero(N);
        for (gadget, input) in gadgets[..count].iter().zip(&inputs[..count]) {
            gadget.external_product_to(input, &mut product, &basis, &mut fft, &mut workspace);
            separate.add_assign(&product, modulus);
        }
        let expected = expected_sum(&inputs[..count], &messages[..count], modulus);
        for ((&actual, &expected), &separate) in output
            .as_ref()
            .iter()
            .zip(expected.as_ref())
            .zip(separate.as_ref())
        {
            for reference in [expected, separate] {
                let distance = actual
                    .wrapping_sub(reference)
                    .min(reference.wrapping_sub(actual));
                assert!(
                    distance <= tolerance,
                    "distance={distance:?}, tolerance={tolerance:?}"
                );
            }
        }
        if count == 0 {
            assert!(output.as_ref().iter().all(|&x| x == T::ZERO));
        }
    }
}
