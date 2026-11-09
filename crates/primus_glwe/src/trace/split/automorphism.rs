//! Split(35) coefficient automorphisms owned by the split trace implementation.
use crate::{FourierGlweEncryptor, GlevParameters};
use aligned_vec::{ABox, avec};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::SignedInteger;
use primus_lattice::{
    GlweSize,
    glev::FourierGlev,
    glwe::{FourierGlwe, Glwe},
};
use primus_modulus::NativeModulus;
use primus_poly::{CoeffAutomorphismPermutation, FourierPolynomial};

/// Two spectra of one exact native key: c = low + 2^35*high (mod 2^64).
#[derive(Clone)]
pub(super) struct SplitGlweAutomorphismKey {
    permutation: CoeffAutomorphismPermutation,
    low: FourierGlev<Vec<Complex64>>,
    high: FourierGlev<Vec<Complex64>>,
}

/// Split products share digit FFTs; inverse transforms need separate accumulators.
pub(super) struct SplitGlweAutomorphismWorkspace<T: TorusFftValue> {
    transformed: Glwe<Vec<T>>,
    high: Glwe<Vec<T>>,
    low_product: FourierGlwe<ABox<[Complex64]>>,
    high_product: FourierGlwe<ABox<[Complex64]>>,
    carries: Box<[bool]>,
    digits: Box<[T]>,
    digit_fft: ABox<[Complex64]>,
}
impl<T: TorusFftValue> SplitGlweAutomorphismWorkspace<T> {
    pub(super) fn new(size: GlweSize) -> Self {
        Self {
            transformed: Glwe::zero(size.glwe_len()),
            high: Glwe::zero(size.glwe_len()),
            low_product: FourierGlwe(
                avec![Complex64::default();size.fourier_glwe_len()].into_boxed_slice(),
            ),
            high_product: FourierGlwe(
                avec![Complex64::default();size.fourier_glwe_len()].into_boxed_slice(),
            ),
            carries: vec![false; size.poly_length().get()].into_boxed_slice(),
            digits: vec![T::ZERO; size.poly_length().get()].into_boxed_slice(),
            digit_fft: avec![Complex64::default();size.fourier_poly_len()].into_boxed_slice(),
        }
    }
}
impl SplitGlweAutomorphismKey {
    /// Generates one positive transformed-secret key. Outer trace generation
    /// validates resources once. Both scratch slices have length N and are
    /// completely overwritten; the owner erases them after all degrees finish.
    pub(super) fn generate<T: TorusFftValue, Table: FftTable, R: rand::Rng + rand::CryptoRng>(
        degree: usize,
        encryptor: &mut FourierGlweEncryptor<'_, T>,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        transformed: &mut [T::SignedInteger],
        limb: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> Self {
        let n = parameters.poly_length().get();
        let permutation = CoeffAutomorphismPermutation::new(degree, parameters.poly_length());
        permutation.apply_signed_to::<T>(encryptor.coefficient_secret().as_slice(), transformed);
        let mut low = FourierGlev::zero(parameters.fourier_glev_len());
        let mut high = FourierGlev::zero(parameters.fourier_glev_len());
        for ((weight, mut low_row), mut high_row) in parameters
            .basis()
            .scalar_iter()
            .zip(low.iter_glwe_mut(parameters.glwe_size().fourier_glwe_len()))
            .zip(high.iter_glwe_mut(parameters.glwe_size().fourier_glwe_len()))
        {
            // Exact native addition commutes with the mask product: adding the
            // message before that product preserves the previous coefficients
            // and noise->mask RNG order. Split only the completed row.
            let row = encryptor.sample_row(parameters.encryption_parameters(), rng, |body| {
                for (b, &s) in body.iter_mut().zip(transformed.iter()) {
                    *b = b.wrapping_add(weight.wrapping_mul(s.cast_to_unsigned()));
                }
            });
            for ((input, mut low_poly), mut high_poly) in row
                .iter_poly(n)
                .zip(low_row.iter_fourier_poly_mut(n / 2))
                .zip(high_row.iter_fourier_poly_mut(n / 2))
            {
                for (out, &v) in limb.iter_mut().zip(input.as_ref()) {
                    *out = v & ((T::ONE << 35u32) - T::ONE);
                }
                fft.forward_as_torus(limb, low_poly.as_mut());
                for (out, &v) in limb.iter_mut().zip(input.as_ref()) {
                    *out = v >> 35u32;
                }
                // Both segments retain the same torus scale, 2^-64.
                fft.forward_as_torus(limb, high_poly.as_mut());
            }
        }
        Self {
            permutation,
            low,
            high,
        }
    }

    /// Applies to validated native coefficient GLWEs, subtracting the positive
    /// switching-key product. Reconstruct only after separate inverse rounding.
    pub(super) fn apply_kernel_to<T: TorusFftValue, Table: FftTable>(
        &self,
        basis: &ApproxSignedBasis<T>,
        input: Glwe<&[T]>,
        mut output: Glwe<&mut [T]>,
        fft: &mut FftEngine<'_, Table>,
        work: &mut SplitGlweAutomorphismWorkspace<T>,
    ) {
        let n = fft.poly_length().get();
        for (input, mut out) in input.iter_poly(n).zip(work.transformed.iter_poly_mut(n)) {
            self.permutation
                .apply_to(input.as_ref(), out.as_mut(), NativeModulus::new());
        }
        work.low_product.set_zero();
        work.high_product.set_zero();
        let (mask, body) = work.transformed.a_b_slices(n);
        basis.init_carry_slice(mask, &mut work.carries);
        for ((decomposer, low), high) in basis
            .decomposer_iter()
            .zip(self.low.iter_glwe(n))
            .zip(self.high.iter_glwe(n))
        {
            decomposer.decompose_slice_to(mask, &mut work.digits, &mut work.carries);
            fft.forward_as_integer(&work.digits, &mut work.digit_fft);
            let digit = FourierPolynomial::new(&*work.digit_fft);
            work.low_product
                .add_mul_fourier_polynomial_assign(&low, &digit);
            work.high_product
                .add_mul_fourier_polynomial_assign(&high, &digit);
        }
        work.low_product.write_torus_form(&mut output, fft);
        output.neg_assign(NativeModulus::new());
        for (b, &v) in output.as_mut()[n..].iter_mut().zip(body.as_ref()) {
            *b = b.wrapping_add(v);
        }
        work.high_product.write_torus_form(&mut work.high, fft);
        for (out, &h) in output.as_mut().iter_mut().zip(work.high.as_ref()) {
            *out = out.wrapping_sub(h << 35u32);
        }
    }
}

#[cfg(all(test, any(feature = "rustfft", feature = "tfhe-fft")))]
mod tests {
    use super::*;
    use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
    use primus_lattice::GlweDimension;
    use primus_shape::PolyLength;

    /// Reproduce the former Split35 sampling/addition order with an independent
    /// native gather convolution, rather than calling the shared CRT kernel.
    fn reference_row(
        secret: &[i64],
        params: &crate::GlweEncryptionParameters<u64, NativeModulus<u64>>,
        message: &[u64],
        rng: &mut rand::rngs::StdRng,
    ) -> Vec<u64> {
        let n = secret.len();
        let mut row = vec![0u64; 2 * n];
        let (mask, body) = row.split_at_mut(n);
        primus_distr::sample_gaussian_values_to(body, params.noise_distribution(), rng);
        primus_distr::sample_uniform_values_to(mask, &params.cipher_modulus_uniform_distr(), rng);
        for (degree, b) in body.iter_mut().enumerate() {
            for (j, &s) in secret.iter().enumerate() {
                let i = (degree + n - j) & (n - 1);
                let product = mask[i].wrapping_mul(s as u64);
                *b = if i + j < n {
                    b.wrapping_add(product)
                } else {
                    b.wrapping_sub(product)
                };
            }
            *b = b.wrapping_add(message[degree]);
        }
        row
    }

    /// Inspect private limbs without adding raw-key or diagnostic public APIs.
    /// Rebinding length/secret creates a fresh setup; ordinary rows before/after
    /// the trace exercise overwriting the same buffer and continuing its RNG.
    fn shared_rows<Table: FftTable>() {
        use crate::{GlweSecretKey, SecretKeyDistr, SplitFourierGlweTraceKey};
        use primus_decompose::DecompositionConfig;
        use primus_lattice::glev::Glev;
        use rand::{Rng, SeedableRng, rngs::StdRng};

        for n in [32, 64] {
            let length = PolyLength::new(n);
            let params = GlevParameters::try_new(
                GlweSize::new(GlweDimension::new(1), length),
                NativeModulus::new(),
                SecretKeyDistr::UniformTernary,
                DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(7),
                    level_count: Some(DecompositionLevelCount::new(6)),
                },
                0.7,
            )
            .unwrap();
            let secret: Vec<i64> = (0..n).map(|i| [-1, 0, 1][(i + n / 32) % 3]).collect();
            let key = GlweSecretKey::new(
                secret.clone(),
                params.glwe_size(),
                SecretKeyDistr::UniformTernary,
            );
            let mut encryptor =
                FourierGlweEncryptor::try_new(&key, params.encryption_parameters()).unwrap();
            let table = Table::new(length);
            let mut fft = FftEngine::new(&table);
            let mut rng = StdRng::seed_from_u64(105);
            let mut reference_rng = StdRng::seed_from_u64(105);
            let zero = vec![0u64; n];
            let expected = reference_row(
                &secret,
                params.encryption_parameters(),
                &zero,
                &mut reference_rng,
            );
            assert_eq!(
                encryptor
                    .sample_row(params.encryption_parameters(), &mut rng, |_| {})
                    .as_ref(),
                expected
            );
            let trace =
                SplitFourierGlweTraceKey::generate(&mut encryptor, &params, &mut fft, &mut rng);
            assert_eq!(trace.keys.len(), length.log_n() as usize);
            for (key, shift) in trace.keys.iter().zip((1..=length.log_n()).rev()) {
                // Independent signed automorphism; all destination coefficients
                // are overwritten because the odd degree permutes the ring.
                let degree = (1 << shift) + 1;
                let mut transformed = vec![0u64; n];
                for (i, &s) in secret.iter().enumerate() {
                    let exponent = (i * degree) & (2 * n - 1);
                    transformed[exponent & (n - 1)] = if exponent < n {
                        s as u64
                    } else {
                        (s as u64).wrapping_neg()
                    };
                }
                let mut coefficients = Vec::new();
                for weight in params.basis().scalar_iter() {
                    let message: Vec<_> =
                        transformed.iter().map(|s| s.wrapping_mul(weight)).collect();
                    coefficients.extend(reference_row(
                        &secret,
                        params.encryption_parameters(),
                        &message,
                        &mut reference_rng,
                    ));
                }
                let mut reconstructed = vec![0u64; coefficients.len()];
                for (spectrum, shift, mask) in
                    [(&key.low, 0, (1u64 << 35) - 1), (&key.high, 35, u64::MAX)]
                {
                    let expected: Vec<_> =
                        coefficients.iter().map(|v| (v >> shift) & mask).collect();
                    let native = Glev::new(expected.as_slice());
                    let mut expected_spectrum =
                        FourierGlev::<Vec<Complex64>>::zero(params.fourier_glev_len());
                    native.write_fourier_form(&mut expected_spectrum, &mut fft);
                    assert_eq!(spectrum.as_ref(), expected_spectrum.as_ref());
                    let mut actual = Glev::new(vec![0u64; coefficients.len()]);
                    spectrum.write_torus_form(&mut actual, &mut fft);
                    assert_eq!(actual.as_ref(), expected);
                    for (out, &limb) in reconstructed.iter_mut().zip(actual.as_ref()) {
                        *out = out.wrapping_add(limb << shift);
                    }
                }
                assert_eq!(reconstructed, coefficients);
            }
            let expected = reference_row(
                &secret,
                params.encryption_parameters(),
                &zero,
                &mut reference_rng,
            );
            assert_eq!(
                encryptor
                    .sample_row(params.encryption_parameters(), &mut rng, |_| {})
                    .as_ref(),
                expected
            );
            assert_eq!(rng.next_u64(), reference_rng.next_u64());
        }
    }

    #[test]
    fn shared_setup_preserves_split_rows_limbs_and_rng() {
        #[cfg(feature = "rustfft")]
        shared_rows::<primus_fft::RustFftTable>();
        #[cfg(feature = "tfhe-fft")]
        shared_rows::<primus_fft::TfheFftTable>();
    }

    /// Synthetic key coefficients isolate signed digits, low35 carries, native
    /// sign/wrap and body addition from keygen noise. Oracle uses integer products.
    fn boundaries<Table: FftTable>() {
        let n = 32;
        let length = PolyLength::new(n);
        let table = Table::new(length);
        let mut fft = FftEngine::new(&table);
        let basis = ApproxSignedBasis::<u64>::new(
            None,
            DecompositionBaseLog::new(7),
            Some(DecompositionLevelCount::new(6)),
        );
        let weights: Vec<_> = basis.scalar_iter().collect();
        let edge = [
            0,
            (1u64 << 35) - 1,
            1 << 35,
            (1 << 35) + 1,
            (1 << 63) - 1,
            1 << 63,
            u64::MAX,
        ];
        let coefficients: Vec<_> = (0..6 * 2 * n)
            .map(|i| edge[(i + i / 7) % edge.len()])
            .collect();
        let transform = |shift: u32, mask: u64, fft: &mut FftEngine<'_, Table>| {
            let mut result = FourierGlev::zero(coefficients.len() / 2);
            for (input, mut output) in
                coefficients
                    .chunks_exact(n)
                    .zip(primus_poly::FourierPolynomialIterMut::new(
                        result.as_mut(),
                        n / 2,
                    ))
            {
                let limb: Vec<_> = input.iter().map(|v| (v >> shift) & mask).collect();
                fft.forward_as_torus(&limb, output.as_mut());
            }
            result
        };
        let key = SplitGlweAutomorphismKey {
            permutation: CoeffAutomorphismPermutation::new(1, length),
            low: transform(0, (1 << 35) - 1, &mut fft),
            high: transform(35, u64::MAX, &mut fft),
        };
        let mut input = Glwe::<Vec<u64>>::zero(2 * n);
        for (i, x) in input.as_mut()[..n].iter_mut().enumerate() {
            for (l, &g) in weights.iter().enumerate() {
                *x = x.wrapping_add(g.wrapping_mul([-64i64, -1, 0, 1, 63][(i + l) % 5] as u64));
            }
        }
        for (i, x) in input.as_mut()[n..].iter_mut().enumerate() {
            *x = edge[i % edge.len()];
        }
        let mut expected = input.clone();
        expected.as_mut()[..n].fill(0);
        // Independent balanced radix division supplies the decomposition oracle.
        let unit = 1i128 << basis.drop_bits();
        let mut quotient: Vec<_> = input.as_ref()[..n]
            .iter()
            .map(|&a| (a as i128 + unit / 2) / unit)
            .collect();
        for level in 0..weights.len() {
            let digits: Vec<_> = quotient
                .iter_mut()
                .map(|q| {
                    let r = q.rem_euclid(128);
                    let d = if r >= 64 { r - 128 } else { r };
                    *q = (*q - d) / 128;
                    d as i64
                })
                .collect();
            for (poly, row) in coefficients[level * 2 * n..(level + 1) * 2 * n]
                .chunks_exact(n)
                .zip(expected.as_mut().chunks_exact_mut(n))
            {
                for (i, &c) in poly.iter().enumerate() {
                    for (j, &d) in digits.iter().enumerate() {
                        let p = c.wrapping_mul(d as u64);
                        let k = (i + j) % n;
                        row[k] = if i + j < n {
                            row[k].wrapping_sub(p)
                        } else {
                            row[k].wrapping_add(p)
                        };
                    }
                }
            }
        }
        let mut output = Glwe::<Vec<u64>>::zero(2 * n);
        key.apply_kernel_to(
            &basis,
            input.as_view(),
            output.as_mut_view(),
            &mut fft,
            &mut SplitGlweAutomorphismWorkspace::new(GlweSize::new(GlweDimension::new(1), length)),
        );
        assert_eq!(output.as_ref(), expected.as_ref());
    }
    #[cfg(feature = "rustfft")]
    #[test]
    fn split_boundaries_rustfft() {
        boundaries::<primus_fft::RustFftTable>();
    }
    #[cfg(feature = "tfhe-fft")]
    #[test]
    fn split_boundaries_tfhe_fft() {
        boundaries::<primus_fft::TfheFftTable>();
    }
}
