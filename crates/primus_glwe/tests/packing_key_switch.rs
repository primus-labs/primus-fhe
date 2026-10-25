use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_fft::{FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{
    FourierGlweGadgetEncryptWorkspace, FourierGlweKeySwitchingWorkspace, FourierGlweSecretKey,
    FourierLwePackingKeySwitchingKey, GlevParameters, GlweParameters, GlweSecretKey, GlweSize,
    NttGlweGadgetEncryptWorkspace, NttGlweKeySwitchingWorkspace, NttGlweSecretKey,
    NttLwePackingKeySwitchingKey, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_lattice::{glwe::Glwe, lwe::Lwe};
use primus_lwe::LweSecretKeyRef;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, U64NttTable};
use primus_shape::PolyLength;
use rand::{RngExt, SeedableRng, rngs::StdRng};

#[allow(dead_code)]
mod common;
use common::{K, N, assert_phase, message, secret};

const INPUT_SECRET: [i64; 7] = [-1, 0, 1, 2, -2, 1, 0];
const Q: u64 = 1_125_899_906_826_241;

// Independent noiseless LWE oracle with mixed-sign, nonbinary secret values.
fn inputs(q: u128, digit_unit: u64, rng: &mut StdRng) -> Vec<u64> {
    let mut batch = vec![0; N * (INPUT_SECRET.len() + 1)];
    for (i, (lwe, m)) in batch
        .as_chunks_mut::<{ INPUT_SECRET.len() + 1 }>()
        .0
        .iter_mut()
        .zip(message(q))
        .enumerate()
    {
        let (body, mask) = lwe.split_last_mut().unwrap();
        let mut b = u128::from(m);
        for (j, (a, s)) in mask.iter_mut().zip(INPUT_SECRET).enumerate() {
            *a = if i == 0 {
                // The single-LWE case exercises 0/±1/±2 and ordinary digits
                // at the highest gadget level, including negative residues.
                let digit = [3i64, 0, -1, 2, -2, 1, -3][j];
                let value = u128::from(digit.unsigned_abs()) * u128::from(digit_unit) % q;
                let value = if digit < 0 { q - value } else { value };
                // One below a gadget multiple propagates a rounding carry through zero digits.
                ((value + q - 1) % q) as u64
            } else {
                (u128::from(rng.random::<u64>()) % q) as u64
            };
            let product = u128::from(*a) * u128::from(s.unsigned_abs()) % q;
            b = (b + if s < 0 { q - product } else { product }) % q;
        }
        *body = b as u64;
    }
    batch
}

fn check_packing(q: u128, batch: &[u64], mut pack: impl FnMut(&[u64], &mut Glwe<Vec<u64>>)) {
    let size = GlweSize::new(GlweDimension::new(K), PolyLength::new(N));
    let mut output = Glwe::new(vec![7; size.glwe_len()]);
    // Reuse the same scratch with shrinking/growing batches; stale tails must not leak.
    for count in [N, 3, 1, N - 1] {
        let mut expected = message(q);
        expected[count..].fill(0);
        pack(&batch[..count * (INPUT_SECRET.len() + 1)], &mut output);
        assert_phase(output.as_ref(), &expected, &secret(), q);
    }
    for (length, output_len) in [
        (0, size.glwe_len()),
        (INPUT_SECRET.len(), size.glwe_len()),
        ((N + 1) * (INPUT_SECRET.len() + 1), size.glwe_len()),
        (INPUT_SECRET.len() + 1, size.glwe_len() - 1),
    ] {
        let mut output = Glwe::new(vec![7; output_len]);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pack(&vec![0; length], &mut output);
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&x| x == 7));
    }
}

fn ntt_packing(log_basis: u32, levels: usize) {
    let modulus = BarrettModulus::new(Q);
    let ntt = U64NttTable::new(PolyLength::new(N), modulus).unwrap();
    let params = GlweParameters::new(
        GlweDimension::new(K),
        PolyLength::new(N),
        64,
        modulus,
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    let glev = GlevParameters::with_glwe_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(log_basis),
            level_count: Some(DecompositionLevelCount::new(levels)),
        },
    );
    let coeff = GlweSecretKey::<u64>::new(secret(), params.size(), SecretKeyDistr::UniformTernary);
    let sk = NttGlweSecretKey::from_coeff_secret_key(&coeff, &ntt);
    let mut rng = StdRng::seed_from_u64(0x5041434b);
    let key = NttLwePackingKeySwitchingKey::generate(
        LweSecretKeyRef::Signed(&INPUT_SECRET),
        &sk,
        &glev,
        &ntt,
        &mut rng,
        &mut NttGlweGadgetEncryptWorkspace::new(glev.size()),
    );
    let batch = inputs(
        u128::from(Q),
        glev.basis().scalar_iter().last().unwrap(),
        &mut rng,
    );
    let mut workspace = NttGlweKeySwitchingWorkspace::new(params.size());
    check_packing(u128::from(Q), &batch, |input, output| {
        if input.len() == INPUT_SECRET.len() + 1 {
            key.key_switch_to(&Lwe::new(input), output, modulus, &ntt, &mut workspace);
        } else {
            key.pack_lwes_to(input, output, modulus, &ntt, &mut workspace);
        }
    });
    let wrong_modulus = BarrettModulus::new(132_120_577u64);
    let wrong_table = U64NttTable::new(PolyLength::new(N), wrong_modulus).unwrap();
    let wrong_length = U64NttTable::new(PolyLength::new(N * 2), modulus).unwrap();
    for (modulus, table, size) in [
        (wrong_modulus, &ntt, params.size()),
        (modulus, &wrong_table, params.size()),
        (modulus, &wrong_length, params.size()),
        (
            modulus,
            &ntt,
            GlweSize::new(GlweDimension::new(K + 1), PolyLength::new(N)),
        ),
        (
            modulus,
            &ntt,
            GlweSize::new(GlweDimension::new(K), PolyLength::new(2 * N)),
        ),
    ] {
        let mut output = Glwe::new(vec![7; params.glwe_len()]);
        let mut workspace = NttGlweKeySwitchingWorkspace::new(size);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                key.pack_lwes_to(&batch, &mut output, modulus, table, &mut workspace);
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&x| x == 7));
    }
}

#[test]
fn ntt_packing_switches_an_independent_signed_lwe_secret() {
    // Cover the specialized small-digit kernel and the general multiply-add kernel.
    for (log_basis, levels) in [(3, 10), (10, 3)] {
        ntt_packing(log_basis, levels);
    }
}

fn fourier_packing<Table: FftTable>(log_basis: u32, levels: usize) {
    let table = Table::new(PolyLength::new(N));
    let mut fft = FftEngine::new(&table);
    let params = GlweParameters::new(
        GlweDimension::new(K),
        PolyLength::new(N),
        64u64,
        NativeModulus::new(),
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    let glev = GlevParameters::with_glwe_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(log_basis),
            level_count: Some(DecompositionLevelCount::new(levels)),
        },
    );
    let coeff = GlweSecretKey::<u64>::new(secret(), params.size(), SecretKeyDistr::UniformTernary);
    let sk = FourierGlweSecretKey::from_coeff_secret_key(&coeff, &mut fft);
    let mut rng = StdRng::seed_from_u64(0x5041434b);
    let encoded = INPUT_SECRET.map(|x| x as u64);
    let key = FourierLwePackingKeySwitchingKey::generate(
        LweSecretKeyRef::Encoded(&encoded),
        &sk,
        &glev,
        &mut fft,
        &mut rng,
        &mut FourierGlweGadgetEncryptWorkspace::new(glev.size()),
    );
    let batch = inputs(
        1u128 << 64,
        glev.basis().scalar_iter().last().unwrap(),
        &mut rng,
    );
    let mut workspace = FourierGlweKeySwitchingWorkspace::new(params.size());
    check_packing(1u128 << 64, &batch, |input, output| {
        if input.len() == INPUT_SECRET.len() + 1 {
            key.key_switch_to(&Lwe::new(input), output, &mut fft, &mut workspace);
        } else {
            key.pack_lwes_to(input, output, &mut fft, &mut workspace);
        }
    });
    let wrong_table = Table::new(PolyLength::new(2 * N));
    let mut wrong_fft = FftEngine::new(&wrong_table);
    for (fft, size) in [
        (&mut wrong_fft, params.size()),
        (
            &mut fft,
            GlweSize::new(GlweDimension::new(K + 1), PolyLength::new(N)),
        ),
    ] {
        let mut output = Glwe::new(vec![7; params.glwe_len()]);
        let mut workspace = FourierGlweKeySwitchingWorkspace::new(size);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                key.pack_lwes_to(&batch, &mut output, fft, &mut workspace);
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&x| x == 7));
    }
}

#[test]
fn fourier_packing_switches_an_independent_encoded_lwe_secret() {
    for (log_basis, levels) in [(3, 10), (10, 3)] {
        fourier_packing::<RustFftTable>(log_basis, levels);
        fourier_packing::<TfheFftTable>(log_basis, levels);
    }
}
