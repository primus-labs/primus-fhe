#![cfg(any(feature = "rustfft", feature = "tfhe-fft"))]

use primus_decompose::{DecompositionBaseLog, primitive::ApproxSignedBasis};
use primus_encoding::PlaintextEmbedding;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::{AsFrom, SignedInteger};
use primus_modulus::NativeModulus;
use primus_ntru::{
    FourierNlevCiphertext, FourierNtruEncryptWorkspace, FourierNtruGadgetEncryptWorkspace,
    FourierNtruSecretKey, NlevCiphertext, NlevParameters, NtruCiphertext, NtruParameters,
    NtruSecretKey, SecretKeyDistr,
};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};

fn schoolbook_phase<T: TorusFftValue>(ciphertext: &[T], secret: &[T]) -> Vec<T> {
    let n = secret.len();
    let mut phase = vec![T::ZERO; n];
    for (i, &f) in secret.iter().enumerate() {
        for (j, &c) in ciphertext.iter().enumerate() {
            let product = f.wrapping_mul(c);
            if i + j < n {
                phase[i + j] = phase[i + j].wrapping_add(product);
            } else {
                phase[i + j - n] = phase[i + j - n].wrapping_sub(product);
            }
        }
    }
    phase
}

fn check_native_rows<T: TorusFftValue, Table: FftTable>() {
    // Degree 64 crosses the recursive multiplication threshold. Negative and
    // separated coefficients exercise wrapping and the negacyclic sign.
    let length = PolyLength::new(64);
    let n = length.get();
    let table = Table::new(length);
    let mut fft = FftEngine::new(&table);
    let distribution = SecretKeyDistr::SparseTernary;
    let mut signed = vec![T::SignedInteger::as_from(0i32); n];
    for (index, value) in [(0, 1), (9, -1), (37, 1)] {
        signed[index] = T::SignedInteger::as_from(value);
    }
    let secret = signed
        .iter()
        .map(|&value| value.cast_to_unsigned())
        .collect::<Vec<_>>();
    let key = FourierNtruSecretKey::try_from_coeff_secret_key(
        &NtruSecretKey::<T>::new(signed, distribution),
        &mut fft,
    )
    .unwrap();
    let params = NtruParameters::new(
        length,
        T::as_from(16u32),
        NativeModulus::new(),
        distribution,
        0.7,
    );
    let basis = ApproxSignedBasis::new(
        params.encryption_parameters().cipher_modulus_value(),
        DecompositionBaseLog::new(8),
        None,
    );
    let gadget = NlevParameters::try_with_basis(&params, basis).unwrap();
    let mut workspace = FourierNtruEncryptWorkspace::new(length);
    let mut gadget_workspace = FourierNtruGadgetEncryptWorkspace::new(length);
    let message = Polynomial(
        (0..n)
            .map(|i| T::as_from((i % 16) as u32))
            .collect::<Vec<_>>(),
    );
    let mut coefficient = NtruCiphertext::<Vec<T>>::zero(n);
    let mut rng = StdRng::seed_from_u64(41);
    let mut phase_rng = StdRng::seed_from_u64(41);
    let mut fourier_rng = StdRng::seed_from_u64(41);
    key.encrypt_message_coeff_to(
        &message,
        &mut coefficient,
        &params,
        PlaintextEmbedding::Centered,
        &mut rng,
        &mut workspace,
    );
    let mut phase = vec![T::ZERO; n];
    primus_distr::sample_gaussian_values_to(
        &mut phase,
        params.encryption_parameters().noise_distribution(),
        &mut phase_rng,
    );
    params.plaintext_codec().add_encode_slice_assign(
        &mut phase,
        message.as_ref(),
        PlaintextEmbedding::Centered,
    );
    assert_eq!(schoolbook_phase(coefficient.as_ref(), &secret), phase);
    let fourier = key.encrypt_message(
        &message,
        &params,
        PlaintextEmbedding::Centered,
        &mut fft,
        &mut fourier_rng,
        &mut workspace,
    );
    let mut expected = vec![Complex64::default(); length.fourier_poly_len()];
    fft.forward_as_torus(coefficient.as_ref(), &mut expected);
    assert_eq!(fourier.as_ref(), &expected);

    for bit in [false, true] {
        for lift in [false, true] {
            let mut coefficients = NlevCiphertext::<Vec<T>>::zero(gadget.nlev_len());
            let mut rng = StdRng::seed_from_u64(53);
            let mut phase_rng = StdRng::seed_from_u64(53);
            let mut fourier_rng = StdRng::seed_from_u64(53);
            key.encrypt_gadget_bit_coeff_to(
                bit,
                lift,
                coefficients.as_mut_view(),
                &gadget,
                &mut rng,
                &mut gadget_workspace,
            );
            for (row, scalar) in coefficients
                .as_ref()
                .chunks_exact(n)
                .zip(gadget.basis().scalar_iter())
            {
                primus_distr::sample_gaussian_values_to(
                    &mut phase,
                    params.encryption_parameters().noise_distribution(),
                    &mut phase_rng,
                );
                if bit && lift {
                    phase[0] = phase[0].wrapping_add(scalar);
                } else if bit {
                    for (out, &f) in phase.iter_mut().zip(&secret) {
                        *out = out.wrapping_add(scalar.wrapping_mul(f));
                    }
                }
                assert_eq!(schoolbook_phase(row, &secret), phase);
            }

            let mut fourier =
                FourierNlevCiphertext::<Vec<Complex64>>::zero(gadget.fourier_nlev_len());
            if lift {
                key.encrypt_nlev_constant_to(
                    T::as_from(u32::from(bit)),
                    &mut fourier,
                    &gadget,
                    &mut fft,
                    &mut fourier_rng,
                    &mut gadget_workspace,
                );
            } else {
                key.encrypt_ngsw_signed_constant_batch_to(
                    &[T::SignedInteger::as_from(i32::from(bit))],
                    fourier.as_mut(),
                    &gadget,
                    &mut fft,
                    &mut fourier_rng,
                    &mut gadget_workspace,
                );
            }
            for (row, spectrum) in coefficients
                .as_ref()
                .chunks_exact(n)
                .zip(fourier.as_ref().chunks_exact(length.fourier_poly_len()))
            {
                fft.forward_as_torus(row, &mut expected);
                assert_eq!(spectrum, &expected);
            }
            let next = rng.next_u64();
            assert_eq!(next, phase_rng.next_u64());
            assert_eq!(next, fourier_rng.next_u64());
        }
    }
}

#[cfg(feature = "rustfft")]
#[test]
fn rustfft_rows_start_in_the_native_ring() {
    check_native_rows::<u16, primus_fft::RustFftTable>();
    check_native_rows::<u32, primus_fft::RustFftTable>();
    check_native_rows::<u64, primus_fft::RustFftTable>();
}

#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_rows_start_in_the_native_ring() {
    check_native_rows::<u16, primus_fft::TfheFftTable>();
    check_native_rows::<u32, primus_fft::TfheFftTable>();
    check_native_rows::<u64, primus_fft::TfheFftTable>();
}
