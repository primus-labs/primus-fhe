//! Gadget level order, coefficient/transform endpoints and scratch reuse.
//! Nonzero products exercise the arithmetic; zero products must clear dirty
//! outputs without retaining contributions from the preceding call.

use primus_decompose::DecompositionBaseLog;
use primus_decompose::primitive::ApproxSignedBasis;
#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
use primus_fft::{Complex64, FftEngine, FftTable};
#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
use primus_lattice::{
    GadgetSize, GlweDimension, GlweSize,
    ggsw::FourierGgswOwned,
    glwe::{FourierGlwe, Glwe},
    ngsw::FourierNgswOwned,
    nlev::FourierNlevOwned,
    ntru::FourierNtru,
    workspace::{FourierGlweExternalProductWorkspace, FourierNtruExternalProductWorkspace},
};
use primus_lattice::{ngsw::Ngsw, ntru::Ntru};
#[cfg(feature = "ntt")]
use primus_lattice::{nlev::NttNlev, ntru::NttNtru, workspace::NttNtruExternalProductWorkspace};
#[cfg(feature = "ntt")]
use primus_modulus::BarrettModulus;
#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
use primus_modulus::NativeModulus;
#[cfg(feature = "ntt")]
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
#[cfg(feature = "ntt")]
use primus_shape::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
use super::unit_ggsw;
use super::{N, POLY_LENGTH, noiseless_nlev};

// A diagonal gadget for one is an identity external product. Applying a zero
// gadget afterwards must clear both a nonzero output and the reused accumulator.
#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
pub(super) fn check_fourier_ggsw<Table: FftTable>(fft: &Table) {
    let mut engine = FftEngine::new(fft);
    let components = 3;
    let basis = ApproxSignedBasis::<u32>::new(None, DecompositionBaseLog::new(8), None);
    let size = GadgetSize::new(
        GlweSize::new(GlweDimension::new(components - 1), POLY_LENGTH),
        basis.level_count(),
    );
    let gadget = unit_ggsw(size, &basis);
    let mut key = FourierGgswOwned::zero(size.fourier_ggsw_len());
    gadget.write_fourier_form(&mut key, &mut engine);
    let values: Vec<u32> = (0..components * N)
        .map(|i| (i as u32).wrapping_mul(0x9e37_79b9))
        .collect();
    let input = Glwe::new(values.clone());
    let mut output = Glwe::new(vec![u32::MAX; values.len()]);
    let mut transformed = FourierGlwe::new(vec![
        Complex64::new(1.0, -1.0);
        components * fft.fourier_length()
    ]);
    let mut workspace = FourierGlweExternalProductWorkspace::new(size);
    let zeros = vec![0; values.len()];
    for nonzero in [true, false] {
        if !nonzero {
            key.set_zero();
        }
        let expected = if nonzero { &values } else { &zeros };
        key.external_product_to(&input, &mut output, &basis, &mut engine, &mut workspace);
        assert_eq!(output.as_ref(), expected);

        // The Fourier endpoint uses its destination as the accumulator instead
        // of workspace storage. Neither buffer needs clearing between calls.
        key.external_product_fourier_to(
            &input,
            &mut transformed,
            &basis,
            &mut engine,
            &mut workspace,
        );
        if !nonzero {
            assert!(transformed.as_ref().iter().all(|&x| x == Complex64::ZERO));
        }
        transformed.write_torus_form(&mut output, &mut engine);
        assert_eq!(output.as_ref(), expected);
    }
}

#[cfg(feature = "ntt")]
#[test]
fn ntt_ntru_gadget_products_match_negacyclic_product() {
    const Q: u32 = 257;

    let modulus = BarrettModulus::new(Q);
    let ntt = UintNttTable::<u32>::new(POLY_LENGTH, modulus).unwrap();
    let basis = ApproxSignedBasis::new(Some(Q), DecompositionBaseLog::new(3), None);

    let alpha = Polynomial::<Vec<u32>>::new(
        vec![
            0, 1, 8, 63, 64, 127, 128, 192, 255, 256, 17, 33, 65, 129, 193, 241,
        ]
        .repeat(N / 16),
    );
    let mut beta = Polynomial::<Vec<u32>>::zero(N);

    let mut workspace = NttNtruExternalProductWorkspace::new(POLY_LENGTH);
    let mut nlev_product = Ntru::new(vec![u32::MAX; N]);
    let input_ntru = Ntru::new(alpha.as_ref());
    let mut ngsw_product = Ntru::new(vec![u32::MAX; N]);
    let mut storage = [u32::MAX; N + 2];
    let mut transformed = NttNtru::new(&mut storage[1..=N]);

    // Nonzero then zero products must overwrite prior outputs and workspace state.
    for amplitude in [7, 0] {
        beta.as_mut()[3] = amplitude;
        let coeff_nlev = noiseless_nlev(&beta, &basis, modulus);
        let coeff_ngsw = Ngsw::new(coeff_nlev.as_ref().to_vec());
        let ntt_nlev = coeff_nlev.into_ntt_form(&ntt);
        let ntt_ngsw = coeff_ngsw.into_ntt_form(&ntt);

        if amplitude != 0 {
            // The public coefficient-output boundary rejects a short buffer
            // before clearing it. The valid calls below reuse the same scratch.
            let mut short = Ntru::new([u32::MAX; N - 1]);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    ntt_ngsw.external_product_to(
                        &input_ntru,
                        &mut short,
                        &basis,
                        modulus,
                        &ntt,
                        &mut workspace,
                    );
                }))
                .is_err()
            );
            assert_eq!(short.as_ref(), &[u32::MAX; N - 1]);
        }

        let mut expected = Polynomial::<Vec<u32>>::zero(N);
        alpha.naive_mul_to(&beta, &mut expected, modulus);

        ntt_nlev.external_product_to(
            &alpha,
            &mut nlev_product,
            &basis,
            modulus,
            &ntt,
            &mut workspace,
        );
        assert_eq!(nlev_product.as_ref(), expected.as_ref());

        ntt_ngsw.external_product_to(
            &input_ntru,
            &mut ngsw_product,
            &basis,
            modulus,
            &ntt,
            &mut workspace,
        );
        assert_eq!(ngsw_product.as_ref(), expected.as_ref());

        // Nonzero borrowed destinations exercise output-backed accumulators.
        ntt_nlev.external_product_ntt_to(
            &alpha,
            &mut transformed,
            &basis,
            modulus,
            &ntt,
            &mut workspace,
        );
        if amplitude == 0 {
            assert!(transformed.as_ref().iter().all(|&x| x == 0));
        }
        transformed.write_coeff_form(&mut nlev_product, &ntt);
        assert_eq!(nlev_product.as_ref(), expected.as_ref());
        ntt_ngsw.external_product_ntt_to(
            &input_ntru,
            &mut transformed,
            &basis,
            modulus,
            &ntt,
            &mut workspace,
        );
        if amplitude == 0 {
            assert!(transformed.as_ref().iter().all(|&x| x == 0));
        }
        transformed.write_coeff_form(&mut ngsw_product, &ntt);
        assert_eq!(ngsw_product.as_ref(), expected.as_ref());
    }
    assert_eq!([storage[0], storage[N + 1]], [u32::MAX; 2]);
}

// Both FFT backends must preserve torus scale at coefficient and Fourier endpoints.
#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
pub(super) fn check_fourier_ntru<Table: FftTable>(fft: &Table) {
    let modulus = NativeModulus::<u32>::new();
    let basis = ApproxSignedBasis::<u32>::new(None, DecompositionBaseLog::new(8), None);
    let mut engine = FftEngine::new(fft);

    let alpha = Polynomial::<Vec<u32>>::new(
        vec![
            0x0123_4567,
            0x89ab_cdef,
            0xfedc_ba98,
            0x7654_3210,
            0x1357_9bdf,
            0x2468_ace0,
            0xffff_ffff,
            0x8000_0000,
            0x7fff_ffff,
            0xdead_beef,
            0xcafe_babe,
            0x1020_3040,
            0x5566_7788,
            0xaabb_ccdd,
            0x3141_5926,
            0x2718_2818,
        ]
        .repeat(N / 16),
    );
    let mut beta = Polynomial::<Vec<u32>>::zero(N);

    let mut workspace = FourierNtruExternalProductWorkspace::new(POLY_LENGTH);
    let mut nlev_product = Ntru::new(vec![u32::MAX; N]);
    let input_ntru = Ntru::new(alpha.as_ref());
    let mut ngsw_product = Ntru::new(vec![u32::MAX; N]);
    let guard = Complex64::new(17.0, -23.0);
    let mut storage = [guard; N / 2 + 2];
    let mut transformed = FourierNtru::new(&mut storage[1..=N / 2]);

    // Nonzero then zero products must overwrite prior outputs and workspace state.
    for amplitude in [1, 0] {
        beta.as_mut()[5] = amplitude;
        let coeff_nlev = noiseless_nlev(&beta, &basis, modulus);
        let coeff_ngsw = Ngsw::new(coeff_nlev.as_ref().to_vec());

        let fourier_length = basis.level_count().get() * fft.fourier_length();
        let mut fourier_nlev = FourierNlevOwned::zero(fourier_length);
        coeff_nlev.write_fourier_form(&mut fourier_nlev, &mut engine);
        let mut fourier_ngsw = FourierNgswOwned::zero(fourier_length);
        coeff_ngsw.write_fourier_form(&mut fourier_ngsw, &mut engine);

        if amplitude != 0 {
            // This endpoint borrows the output as its accumulator; reject a
            // short buffer before zeroing it or changing the reused workspace.
            let mut short = FourierNtru::new([guard; N / 2 - 1]);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    fourier_ngsw.external_product_fourier_to(
                        &input_ntru,
                        &mut short,
                        &basis,
                        &mut engine,
                        &mut workspace,
                    );
                }))
                .is_err()
            );
            assert_eq!(short.as_ref(), &[guard; N / 2 - 1]);
        }

        let mut expected = Polynomial::<Vec<u32>>::zero(N);
        alpha.naive_mul_to(&beta, &mut expected, modulus);

        fourier_nlev.external_product_to(
            &alpha,
            &mut nlev_product,
            &basis,
            &mut engine,
            &mut workspace,
        );
        assert_eq!(nlev_product.as_ref(), expected.as_ref());

        fourier_ngsw.external_product_to(
            &input_ntru,
            &mut ngsw_product,
            &basis,
            &mut engine,
            &mut workspace,
        );
        assert_eq!(ngsw_product.as_ref(), expected.as_ref());

        fourier_nlev.external_product_fourier_to(
            &alpha,
            &mut transformed,
            &basis,
            &mut engine,
            &mut workspace,
        );
        if amplitude == 0 {
            assert!(
                transformed
                    .as_ref()
                    .iter()
                    .all(|&x| x == Complex64::default())
            );
        }
        transformed.write_torus_form(&mut nlev_product, &mut engine);
        assert_eq!(nlev_product.as_ref(), expected.as_ref());
        fourier_ngsw.external_product_fourier_to(
            &input_ntru,
            &mut transformed,
            &basis,
            &mut engine,
            &mut workspace,
        );
        if amplitude == 0 {
            assert!(
                transformed
                    .as_ref()
                    .iter()
                    .all(|&x| x == Complex64::default())
            );
        }
        transformed.write_torus_form(&mut ngsw_product, &mut engine);
        assert_eq!(ngsw_product.as_ref(), expected.as_ref());
    }
    assert_eq!([storage[0], storage[N / 2 + 1]], [guard; 2]);
}

// Scalar digits and coefficient convolution independently check the eight
// branches, including automorphism signs. No NTT multiplication is used by the oracle.
#[cfg(feature = "ntt")]
fn prepermuted_sum_oracle<
    T: primus_integer::FheUint,
    Table: NttTable<ValueT = T>,
    const K: usize,
>(
    modulus: BarrettModulus<T>,
    table: &Table,
    degrees: [usize; K],
    identity: bool,
) {
    let n = table.poly_length().get();
    let q: u128 = modulus.value().as_into();
    let basis = ApproxSignedBasis::new(Some(modulus.value()), DecompositionBaseLog::new(4), None);
    let count = basis.level_count().get();
    let mut keys: Vec<_> = (0..=K)
        .map(|branch| {
            Ngsw::new(
                (0..n * count)
                    .map(|i| T::as_from((q - 1 + i as u128 * 17 + branch as u128 * 31) % q))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    let input = Ntru::new(
        (0..n)
            .map(|i| T::as_from([0, 8, 7, 9, q - 1, q - 2, q / 2, q / 2 + 1][i & 7]))
            .collect::<Vec<_>>(),
    );
    let mut workspace = NttNtruExternalProductWorkspace::new(table.poly_length());
    let permutations = degrees
        .map(|degree| primus_ntt::NttAutomorphismPermutation::new(degree, table.poly_length()));
    let mut scratch = vec![T::MAX; (K + 1) * n + 2];
    let mut storage = vec![T::MAX; n + 2];
    for zero in [false, true] {
        if zero {
            for key in &mut keys {
                key.set_zero();
            }
        }
        let mut expected = vec![0u128; n];
        for (i, &value) in input.as_ref().iter().enumerate() {
            let (adjusted, mut carry) = basis.init_value_carry(value);
            for (level, decomposer) in basis.decomposer_iter().enumerate() {
                let (digit, next) = decomposer.decompose(adjusted, carry);
                carry = next;
                let digit: u128 = digit.as_into();
                for (branch, key) in keys.iter().enumerate().skip(usize::from(!identity)) {
                    let degree = if branch == 0 { 1 } else { degrees[branch - 1] };
                    let exponent = (i * degree) & (2 * n - 1);
                    let digit = if exponent >= n {
                        (q - digit) % q
                    } else {
                        digit
                    };
                    for j in 0..n {
                        let coefficient: u128 = key.as_ref()[level * n + j].as_into();
                        let term = digit * coefficient % q;
                        let index = (exponent & (n - 1)) + j;
                        let term = if index >= n { (q - term) % q } else { term };
                        expected[index & (n - 1)] = (expected[index & (n - 1)] + term) % q;
                    }
                }
            }
        }
        let mut transformed: Vec<_> = keys
            .iter()
            .map(|key| Ngsw::new(key.as_ref().to_vec()).into_ntt_form(table))
            .collect();
        let mut permuted = vec![T::ZERO; n];
        for (i, key) in transformed.iter_mut().enumerate().skip(1) {
            let inverse = primus_ntt::NttAutomorphismPermutation::new(
                (1..2 * n)
                    .step_by(2)
                    .find(|&d| (d * degrees[i - 1]) & (2 * n - 1) == 1)
                    .unwrap(),
                table.poly_length(),
            );
            for mut row in key.iter_ntt_ntru_mut(n) {
                inverse.apply_to(row.as_ref(), &mut permuted);
                row.as_mut().copy_from_slice(&permuted);
            }
        }
        let branches: [_; K] =
            std::array::from_fn(|i| (NttNlev::new(transformed[i + 1].as_ref()), &permutations[i]));
        let mut output = NttNtru::new(&mut storage[1..=n]);
        NttNlev::external_product_prepermuted_sum_ntt_to(
            identity.then(|| NttNlev::new(transformed[0].as_ref())),
            branches,
            input.as_view(),
            output.as_mut_view(),
            &basis,
            modulus,
            table,
            &mut scratch[1..=(K + 1) * n],
            &mut workspace,
        );
        table.inverse_transform_slice(output.as_mut());
        assert_eq!(
            output
                .as_ref()
                .iter()
                .copied()
                .map(|x| -> u128 { x.as_into() })
                .collect::<Vec<_>>(),
            expected
        );

        // A truncated branch must be rejected before clearing either destination.
        output.as_mut().fill(T::MAX);
        scratch.fill(T::MAX);
        let mut branches: [_; K] =
            std::array::from_fn(|i| (NttNlev::new(transformed[i + 1].as_ref()), &permutations[i]));
        branches[K - 1].0 = NttNlev::new(&transformed[K].as_ref()[..n * count - 1]);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                NttNlev::external_product_prepermuted_sum_ntt_to(
                    identity.then(|| NttNlev::new(transformed[0].as_ref())),
                    branches,
                    input.as_view(),
                    output.as_mut_view(),
                    &basis,
                    modulus,
                    table,
                    &mut scratch[1..=(K + 1) * n],
                    &mut workspace,
                );
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&x| x == T::MAX));
        assert!(scratch.iter().all(|&x| x == T::MAX));
    }
    assert_eq!([storage[0], storage[n + 1]], [T::MAX; 2]);
    assert_eq!([scratch[0], scratch[(K + 1) * n + 1]], [T::MAX; 2]);
}

#[cfg(feature = "ntt")]
#[test]
fn ntt_prepermuted_sum_matches_coefficient_oracle() {
    for n in [32, 64] {
        let length = PolyLength::new(n);
        let q32 = BarrettModulus::new(65537u32);
        let t32 = primus_ntt::U32NttTable::new(length, q32).unwrap();
        let q64 = BarrettModulus::new(1_125_899_906_826_241u64);
        let t64 = primus_ntt::U64NttTable::new(length, q64).unwrap();
        // Interior pairs are {1,3,5,15}, not an equally spaced R4 subgroup.
        // A missing identity means zero here; the trace caller adds c/4 itself.
        for identity in [false, true] {
            prepermuted_sum_oracle(q32, &t32, [3, 5, 15], identity);
            prepermuted_sum_oracle(q64, &t64, [3, 5, 15], identity);
        }
        prepermuted_sum_oracle(q32, &t32, [1 + n], true);
        prepermuted_sum_oracle(q64, &t64, [1 + n], true);
        let terminal = std::array::from_fn::<_, 7, _>(|i| 1 + (i + 1) * (2 * n / 8));
        prepermuted_sum_oracle(q32, &t32, terminal, true);
        prepermuted_sum_oracle(q64, &t64, terminal, true);
    }
}
