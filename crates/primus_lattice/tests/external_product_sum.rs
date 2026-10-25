//! Fused NLEV sums: independent polynomial oracle, exact NTT differential,
//! Fourier torus error, empty sums, pair counts and dirty workspace reuse.

use primus_decompose::DecompositionBaseLog;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, RustFftTable, TfheFftTable, TorusFftValue};
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
use primus_shape::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 32;

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
        .map(|message| {
            let mut gadget = Nlev::zero(basis.level_count().get() * N);
            for (scalar, mut row) in basis.scalar_iter().zip(gadget.iter_ntru_mut(N)) {
                message.mul_scalar_to(scalar, &mut Polynomial::new(row.as_mut()), modulus);
            }
            gadget
        })
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
    let mut workspace = NttNtruExternalProductWorkspace::new(PolyLength::new(N));
    let mut output = Ntru::new(vec![T::MAX; N]);
    // Counts and output length are checked before writes. The last two cases
    // fail after a valid first product, exercising recovery from dirty scratch.
    let gadget_views = [gadgets[0].as_view(), gadgets[1].as_view()];
    let input_views = [inputs[0].as_view(), inputs[1].as_view()];
    let short_input = [
        input_views[0].as_view(),
        Polynomial::new(&inputs[1].as_ref()[..N - 1]),
    ];
    let gadget_len = gadgets[1].as_ref().len();
    let short_gadget = [
        gadget_views[0].as_view(),
        NttNlev::new(&gadgets[1].as_ref()[..gadget_len - 1]),
    ];
    for (gadgets, inputs, output_len, before_writes) in [
        (&gadget_views[..], &input_views[..1], N, true),
        (&gadget_views[..1], &input_views[..], N, true),
        (&gadget_views[..], &input_views[..], N - 1, true),
        (&gadget_views[..], &short_input[..], N, false),
        (&short_gadget[..], &input_views[..], N, false),
    ] {
        output.as_mut().fill(T::ONE);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                NttNlev::external_product_sum_to(
                    gadgets,
                    inputs,
                    Ntru::new(&mut output.as_mut()[..output_len]),
                    &basis,
                    modulus,
                    &table,
                    &mut workspace,
                );
            }))
            .is_err()
        );
        if before_writes {
            assert!(output.as_ref().iter().all(|&x| x == T::ONE));
        }
    }

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
        U32NttTable::new(PolyLength::new(32), BarrettModulus::new(257u32)).unwrap(),
    );
    ntt(
        998_244_353u64,
        U64NttTable::new(PolyLength::new(32), BarrettModulus::new(998_244_353u64)).unwrap(),
    );
}

// The independent integer convolution is the phase oracle for f=1. u64 includes
// low bits that FFT cannot represent exactly; allow an absolute torus error of
// 2^-42 (one unit for u32), not bitwise equality with separately rounded products.
fn fourier<T: TorusFftValue, Table: FftTable>() {
    let modulus = NativeModulus::<T>::new();
    let basis = ApproxSignedBasis::new(None, DecompositionBaseLog::new(8), None);
    let table = Table::new(PolyLength::new(32));
    let mut fft = FftEngine::new(&table);
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
    let mut workspace = FourierNtruExternalProductWorkspace::new(PolyLength::new(N));
    let mut output = Ntru::new(vec![T::MAX; N]);
    let tolerance = T::ONE << T::BITS.saturating_sub(42);
    // Counts and output length are checked before writes. The last two cases
    // fail after a valid first product, exercising recovery from dirty scratch.
    let gadget_views = [gadgets[0].as_view(), gadgets[1].as_view()];
    let input_views = [inputs[0].as_view(), inputs[1].as_view()];
    let short_input = [
        input_views[0].as_view(),
        Polynomial::new(&inputs[1].as_ref()[..N - 1]),
    ];
    let gadget_len = gadgets[1].as_ref().len();
    let short_gadget = [
        gadget_views[0].as_view(),
        FourierNlev::new(&gadgets[1].as_ref()[..gadget_len - 1]),
    ];
    for (gadgets, inputs, output_len) in [
        (&gadget_views[..], &input_views[..1], N),
        (&gadget_views[..1], &input_views[..], N),
        (&gadget_views[..], &input_views[..], N - 1),
        (&gadget_views[..], &short_input[..], N),
        (&short_gadget[..], &input_views[..], N),
    ] {
        output.as_mut().fill(T::ONE);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                FourierNlev::external_product_sum_to(
                    gadgets,
                    inputs,
                    Ntru::new(&mut output.as_mut()[..output_len]),
                    &basis,
                    &mut fft,
                    &mut workspace,
                );
            }))
            .is_err()
        );
        // Fourier keeps its partial sum in scratch until final conversion.
        assert!(output.as_ref().iter().all(|&x| x == T::ONE));
    }

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

#[test]
fn fourier_sum_preserves_torus_phase() {
    fourier::<u32, RustFftTable>();
    fourier::<u64, RustFftTable>();
    fourier::<u32, TfheFftTable>();
    fourier::<u64, TfheFftTable>();
}
