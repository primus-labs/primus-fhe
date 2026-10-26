//! Constant batches preserve polynomial encryption and RNG consumption exactly.

use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_glwe::FourierGlweEncryptor;
use primus_glwe::{
    FourierGgswCiphertext, GlevParameters, GlweParameters, NttGlweGadgetEncryptWorkspace,
    NttGlweSecretKey, SecretKeyDistr,
};
use primus_integer::FheUint;
use primus_lattice::GlweDimension;
use primus_lattice::{
    GadgetSize, GlweSize,
    ggsw::{Ggsw, NttGgsw},
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, U32NttTable, U64NttTable, UintNttTable};
use primus_poly::PolynomialOwned;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[test]
fn ntt_constant_ggsw_batch_matches_individual_encryptions() {
    check_ntt_batch::<u32, UintNttTable<u32>>();
    check_ntt_batch::<u64, UintNttTable<u64>>();
    check_ntt_batch::<u32, U32NttTable>();
    check_ntt_batch::<u64, U64NttTable>();
}

fn check_ntt_batch<T: FheUint, Table: NttTable<ValueT = T>>() {
    let n = 32usize;
    let modulus = BarrettModulus::new(T::try_from(257usize).unwrap());
    let glwe = GlweParameters::new(
        GlweDimension::new(2),
        PolyLength::new(n),
        T::try_from(16usize).unwrap(),
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let params = GlevParameters::with_glwe_params(
        &glwe,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(4),
            level_count: None,
        },
    );
    let table = Table::new(PolyLength::new(n), modulus).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (_, key) = NttGlweSecretKey::generate_pair(
        glwe.size(),
        glwe.encryption_parameters(),
        &table,
        &mut rng,
    );
    let mut workspace = NttGlweGadgetEncryptWorkspace::new(params.size());
    let mut single_workspace = NttGlweGadgetEncryptWorkspace::new(params.size());
    // Coefficient output only needs the polynomial scratch, independent of levels.
    let mut coefficient_workspace = NttGlweGadgetEncryptWorkspace::new(GadgetSize::new(
        params.glwe_size(),
        DecompositionLevelCount::new(1),
    ));
    // Include empty input, binary BSK inputs and general canonical constants.
    let constants = [
        T::ZERO,
        T::ONE,
        modulus.value() - T::ONE,
        T::try_from(17usize).unwrap(),
    ];
    let sentinel = T::try_from(7usize).unwrap();
    for constants in [&constants[..], &constants[..1], &[][..]] {
        let mut batch = vec![sentinel; constants.len() * params.ggsw_len()];
        let mut singles = batch.clone();
        let mut rng = StdRng::seed_from_u64(43);
        let mut single_rng = StdRng::seed_from_u64(43);
        key.encrypt_ggsw_constant_batch_to(
            constants,
            &mut batch,
            &params,
            &table,
            &mut rng,
            &mut workspace,
        );
        let mut message = PolynomialOwned::zero(n);
        for (&constant, chunk) in constants
            .iter()
            .zip(singles.chunks_exact_mut(params.ggsw_len()))
        {
            message.as_mut()[0] = constant;
            key.encrypt_ggsw_to(
                &message,
                &mut NttGgsw::new(chunk),
                &params,
                &table,
                &mut single_rng,
                &mut single_workspace,
            );
        }
        assert_eq!(batch, singles);
        let next_random = single_rng.next_u64();
        assert_eq!(rng.next_u64(), next_random);

        let mut coefficients = vec![sentinel; batch.len()];
        let mut coefficient_rng = StdRng::seed_from_u64(43);
        key.encrypt_ggsw_constant_batch_coeff_to(
            constants,
            &mut coefficients,
            &params,
            &table,
            &mut coefficient_rng,
            &mut coefficient_workspace,
        );
        for block in singles.chunks_exact_mut(params.ggsw_len()) {
            let _ = NttGgsw::new(block).into_coeff_form(&table);
        }
        assert_eq!(coefficients, singles);
        assert_eq!(coefficient_rng.next_u64(), next_random);
    }
    // Layout errors must fail before writing or consuming randomness.
    for (len, coefficient_output, scratch_length) in [
        (params.ggsw_len(), false, n),
        (2 * params.ggsw_len() + 1, false, n),
        (params.ggsw_len(), true, n),
        (2 * params.ggsw_len() + 1, true, n),
        (2 * params.ggsw_len(), true, 2 * n),
    ] {
        let mut workspace = NttGlweGadgetEncryptWorkspace::new(GadgetSize::new(
            GlweSize::new(GlweDimension::new(2), PolyLength::new(scratch_length)),
            params.size().level_count(),
        ));
        let mut output = vec![sentinel; len];
        let mut rng = StdRng::seed_from_u64(43);
        let mut expected_rng = StdRng::seed_from_u64(43);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                if coefficient_output {
                    key.encrypt_ggsw_constant_batch_coeff_to(
                        &constants[..2],
                        &mut output,
                        &params,
                        &table,
                        &mut rng,
                        &mut workspace,
                    );
                } else {
                    key.encrypt_ggsw_constant_batch_to(
                        &constants[..2],
                        &mut output,
                        &params,
                        &table,
                        &mut rng,
                        &mut workspace,
                    );
                }
            }))
            .is_err()
        );
        assert_eq!(output, vec![sentinel; len]);
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}

#[test]
fn fourier_constant_ggsw_batches_match_individual_encryptions() {
    check_fourier_batch::<u32, RustFftTable>();
    check_fourier_batch::<u64, RustFftTable>();
    check_fourier_batch::<u32, TfheFftTable>();
    check_fourier_batch::<u64, TfheFftTable>();
}

fn check_fourier_batch<T: TorusFftValue, Table: FftTable>() {
    let n = 32usize;
    let glwe = GlweParameters::new(
        GlweDimension::new(2),
        PolyLength::new(n),
        T::try_from(16usize).unwrap(),
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let params = GlevParameters::with_glwe_params(
        &glwe,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(3),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    );
    let table = Table::new(PolyLength::new(n));
    let mut fft = FftEngine::new(&table);
    let mut rng = StdRng::seed_from_u64(42);
    let key_coefficients = primus_glwe::GlweSecretKey::generate(
        glwe.size(),
        (glwe.encryption_parameters()).secret_key_sampler(),
        &mut rng,
    );
    let mut key =
        FourierGlweEncryptor::try_new(&key_coefficients, glwe.encryption_parameters()).unwrap();

    let sentinel = Complex64::new(7.0, 9.0);
    // Repeated constants still require independently sampled rows.
    let constants = [
        T::ZERO,
        T::ZERO,
        T::ONE,
        T::ONE,
        T::ZERO,
        T::MAX,
        T::MAX,
        T::MAX / T::try_from(3usize).unwrap(),
    ];
    for input in [&[][..], &constants[..1], &constants[..]] {
        let mut expected = vec![sentinel; input.len() * params.fourier_ggsw_len()];
        let mut actual = expected.clone();
        let mut reference_rng = StdRng::seed_from_u64(43);
        let mut actual_rng = StdRng::seed_from_u64(43);
        let mut message = PolynomialOwned::zero(n);
        for (&constant, block) in input
            .iter()
            .zip(expected.chunks_exact_mut(params.fourier_ggsw_len()))
        {
            message.as_mut()[0] = constant;
            key.encrypt_ggsw_to(
                &message,
                &mut FourierGgswCiphertext::new(block),
                &params,
                &mut fft,
                &mut reference_rng,
            );
        }
        // A preceding nonconstant encryption must not contaminate constant diagonals.
        if let Some(block) = actual.chunks_exact_mut(params.fourier_ggsw_len()).next() {
            message.as_mut().fill(T::ONE);
            key.encrypt_ggsw_to(
                &message,
                &mut FourierGgswCiphertext::new(block),
                &params,
                &mut fft,
                &mut rng,
            );
        }
        key.encrypt_ggsw_constant_batch_to(input, &mut actual, &params, &mut fft, &mut actual_rng);
        assert_eq!(actual, expected);
        let next_random = reference_rng.next_u64();
        assert_eq!(actual_rng.next_u64(), next_random);

        let mut coefficients = vec![T::MAX; input.len() * params.ggsw_len()];
        let mut coefficient_rng = StdRng::seed_from_u64(43);
        key.encrypt_ggsw_constant_batch_coeff_to(
            input,
            &mut coefficients,
            &params,
            &mut coefficient_rng,
        );
        let mut transformed =
            FourierGgswCiphertext::<Vec<Complex64>>::zero(params.fourier_ggsw_len());
        for (fourier, coefficients) in expected
            .chunks_exact(params.fourier_ggsw_len())
            .zip(coefficients.chunks_exact(params.ggsw_len()))
        {
            Ggsw::new(coefficients).write_fourier_form(&mut transformed, &mut fft);
            assert_eq!(fourier, transformed.as_ref());
        }
        assert_eq!(coefficient_rng.next_u64(), next_random);
    }
    for len in [params.fourier_ggsw_len() - 1, params.fourier_ggsw_len() + 1] {
        let mut output = vec![sentinel; len];
        let mut rng = StdRng::seed_from_u64(44);
        let mut expected_rng = StdRng::seed_from_u64(44);
        assert!(
            catch_unwind(AssertUnwindSafe(|| key.encrypt_ggsw_constant_batch_to(
                &constants[..1],
                &mut output,
                &params,
                &mut fft,
                &mut rng
            )))
            .is_err()
        );
        assert!(output.iter().all(|&value| value == sentinel));
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
    for len in [params.ggsw_len() - 1, params.ggsw_len() + 1] {
        let mut output = vec![T::MAX; len];
        let mut rng = StdRng::seed_from_u64(44);
        let mut expected_rng = StdRng::seed_from_u64(44);
        assert!(
            catch_unwind(AssertUnwindSafe(|| key
                .encrypt_ggsw_constant_batch_coeff_to(
                    &constants[..1],
                    &mut output,
                    &params,
                    &mut rng
                )))
            .is_err()
        );
        assert!(output.iter().all(|&value| value == T::MAX));
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}
