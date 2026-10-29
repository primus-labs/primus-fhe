//! Exact native coefficient controls: row phases and prewrite layout boundaries.
#![cfg(feature = "fourier")]

use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_distr::sample_gaussian_values_to;
use primus_lattice::nlev::Nlev;
use primus_modulus::NativeModulus;
use primus_ntru::{
    NlevParameters, NtruParameters, NtruSecretKey, SecretKeyDistr, split::NativeNtruGadgetGenerator,
};
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};

fn parameters(n: usize) -> NlevParameters<u64, NativeModulus<u64>> {
    NlevParameters::with_ntru_params(
        &NtruParameters::new(
            PolyLength::new(n),
            4,
            NativeModulus::new(),
            SecretKeyDistr::gaussian(1.5),
            0.7,
        ),
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(16),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    )
}

#[test]
fn exact_native_control_phases_match_replayed_noise() {
    const N: usize = 32;
    // f = 1 + 2X has odd f(1), and |f(z)| >= 1 on the unit circle,
    // so this fixed key also satisfies ordinary Fourier acceptance assumptions.
    let mut f = vec![0i64; N];
    f[0] = 1;
    f[1] = 2;
    let secret = NtruSecretKey::new(f.clone(), SecretKeyDistr::gaussian(1.5));
    let generator = NativeNtruGadgetGenerator::try_new(&secret).unwrap();
    let parameters = parameters(N);
    for lift in [false, true] {
        for bit in [false, true] {
            let mut rows = vec![u64::MAX; parameters.nlev_len()];
            let mut rng = StdRng::seed_from_u64(0xB10C);
            let mut reference_rng = StdRng::seed_from_u64(0xB10C);
            generator.encrypt_bit_coeff_to(
                bit,
                lift,
                Nlev::new(&mut rows[..]),
                &parameters,
                &mut rng,
            );
            for (row, scalar) in rows
                .as_chunks::<N>()
                .0
                .iter()
                .zip(parameters.basis().scalar_iter())
            {
                // Independent schoolbook negacyclic multiplication, including
                // native overflow. No production inverse or product is reused.
                let mut phase = vec![0u64; N];
                for (i, &coefficient) in f.iter().enumerate() {
                    for (j, &ciphertext) in row.iter().enumerate() {
                        let product = (coefficient as u64).wrapping_mul(ciphertext);
                        let position = (i + j) & (N - 1);
                        phase[position] = if i + j < N {
                            phase[position].wrapping_add(product)
                        } else {
                            phase[position].wrapping_sub(product)
                        };
                    }
                }
                let mut expected = vec![0u64; N];
                sample_gaussian_values_to(
                    &mut expected,
                    parameters.encryption_parameters().noise_distribution(),
                    &mut reference_rng,
                );
                if bit {
                    if lift {
                        expected[0] = expected[0].wrapping_add(scalar);
                    } else {
                        for (coefficient, &secret) in expected.iter_mut().zip(&f) {
                            *coefficient =
                                coefficient.wrapping_add(scalar.wrapping_mul(secret as u64));
                        }
                    }
                }
                assert_eq!(phase, expected);
            }
            assert_eq!(rng.next_u64(), reference_rng.next_u64());
        }
    }
}

#[test]
fn exact_native_control_rejects_layout_before_writing_or_sampling() {
    let generator = NativeNtruGadgetGenerator::try_new(&NtruSecretKey::new(
        [vec![1i64], vec![0; 31]].concat(),
        SecretKeyDistr::gaussian(1.5),
    ))
    .unwrap();
    for (parameters, output_len) in [(parameters(32), 95), (parameters(64), 192)] {
        let mut output = vec![0x1234u64; output_len];
        let original = output.clone();
        let mut rng = StdRng::seed_from_u64(0xB11C);
        let mut original_rng = StdRng::seed_from_u64(0xB11C);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                generator.encrypt_bit_coeff_to(
                    true,
                    true,
                    Nlev::new(&mut output[..]),
                    &parameters,
                    &mut rng,
                );
            }))
            .is_err()
        );
        assert_eq!(output, original);
        assert_eq!(rng.next_u64(), original_rng.next_u64());
    }
}
