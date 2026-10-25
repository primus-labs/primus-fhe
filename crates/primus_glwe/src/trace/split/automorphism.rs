//! Split(35) coefficient automorphisms owned by the split trace implementation.
use super::exact::ExactSecretProduct;

use crate::{GlevParameters, GlweSecretKey};
use aligned_vec::{ABox, avec};
use num_traits::ConstZero;
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
use zeroize::Zeroizing;

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
    /// validates resources once and shares exact convolution setup across degrees.
    pub(super) fn generate<T: TorusFftValue, Table: FftTable, R: rand::Rng + rand::CryptoRng>(
        degree: usize,
        secret: &GlweSecretKey<T>,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        product: &mut ExactSecretProduct,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> Self {
        let n = parameters.poly_length().get();
        let permutation = CoeffAutomorphismPermutation::new(degree, parameters.poly_length());
        let mut transformed = Zeroizing::new(vec![T::SignedInteger::ZERO; n]);
        permutation.apply_signed_to::<T>(secret.as_slice(), &mut transformed);
        let mut mask = vec![T::ZERO; n];
        let mut body = vec![T::ZERO; n];
        let mut convolution = Zeroizing::new(vec![T::ZERO; n]);
        let mut limb = vec![T::ZERO; n];
        let mut low = FourierGlev::zero(parameters.fourier_glev_len());
        let mut high = FourierGlev::zero(parameters.fourier_glev_len());
        for ((weight, mut low_row), mut high_row) in parameters
            .basis()
            .scalar_iter()
            .zip(low.iter_glwe_mut(parameters.glwe_size().fourier_glwe_len()))
            .zip(high.iter_glwe_mut(parameters.glwe_size().fourier_glwe_len()))
        {
            // Preserve ordinary gadget encryption's noise/mask sampling order.
            primus_distr::sample_gaussian_values_to(
                &mut body,
                parameters.encryption_parameters().noise_distribution(),
                rng,
            );
            primus_distr::sample_uniform_values_to(
                &mut mask,
                &parameters
                    .encryption_parameters()
                    .cipher_modulus_uniform_distr(),
                rng,
            );
            product.apply(&mask, &mut convolution);
            for ((b, &p), &s) in body
                .iter_mut()
                .zip(convolution.iter())
                .zip(transformed.iter())
            {
                *b = b
                    .wrapping_add(p)
                    .wrapping_add(weight.wrapping_mul(s.cast_to_unsigned()));
            }
            for ((input, mut low_poly), mut high_poly) in [&mask, &body]
                .into_iter()
                .zip(low_row.iter_fourier_poly_mut(n / 2))
                .zip(high_row.iter_fourier_poly_mut(n / 2))
            {
                for (out, &v) in limb.iter_mut().zip(input) {
                    *out = v & ((T::ONE << 35u32) - T::ONE);
                }
                fft.forward_as_torus(&limb, low_poly.as_mut());
                for (out, &v) in limb.iter_mut().zip(input) {
                    *out = v >> 35u32;
                }
                // Both segments retain the same torus scale, 2^-64.
                fft.forward_as_torus(&limb, high_poly.as_mut());
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
