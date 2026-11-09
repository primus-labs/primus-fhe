//! Fuse the first encrypted rotation with lifting a public polynomial.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_poly::Polynomial;

use crate::ntru::Ntru;
use crate::workspace::FourierNtruCmuxWorkspace;

use super::FourierNlev;

impl<S> FourierNlev<S>
where
    S: Data<Elem = Complex64>,
{
    /// Lifts a public polynomial while applying the first encrypted rotation.
    ///
    /// `self` is `NLEV[1]`; `positive` and optional `negative` are NLEV bit
    /// encryptions. Computes `input ⊙ (self + (R-1)*positive + (R^-1-1)*negative)`
    /// with `R = X^exponent`. Only `input` is decomposed; row multiplication
    /// uses an integer-scale monomial transform. Zero still performs the lift.
    ///
    /// # Correctness
    /// Inherits [`Self::external_product_to`]'s native basis, normalized torus
    /// scale, input/output layout and FFT contracts. All controls use the same
    /// key, basis, exact FFT table instance and `workspace.level_count().get()`
    /// levels. Bits are mutually exclusive; omit `negative` for binary.
    /// `exponent` is already quantized into `0..2N`.
    /// The ideal phase is the basis reconstruction of `input` times
    /// `X^(exponent * (s⁺-s⁻))`, plus control noise and Fourier rounding.
    /// Effective input information below the decomposition resolution can be
    /// lost. Output and scratch are overwritten without allocation or reset.
    ///
    /// # Panics
    /// For nonzero exponents, panics if initializer/combined scratch lengths
    /// differ or FFT/scratch lengths differ during the monomial transform.
    /// Scratch may be partly written; these checks precede output writes.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep controls, public input, transform, and scratch explicit"
    )]
    pub fn lift_monomial_to<T, Table, A, B, C>(
        &self,
        positive: &FourierNlev<A>,
        negative: Option<&FourierNlev<A>>,
        input: &Polynomial<B>,
        exponent: usize,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruCmuxWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = workspace.poly_length().get();
        debug_assert!(exponent < 2 * poly_length);
        debug_assert_eq!(basis.level_count().get(), workspace.level_count().get());
        debug_assert_eq!(positive.as_ref().len(), self.as_ref().len());
        if exponent == 0 {
            self.external_product_to(input, output, basis, fft, &mut workspace.external_product);
            return;
        }

        let mut combined = FourierNlev(workspace.combined_control.as_mut_slice());
        combined.as_mut().copy_from_slice(self.as_ref());
        let product = workspace.external_product.as_mut();
        product.decomposed_poly.fill(T::ZERO);
        let (index, coefficient) = if exponent < poly_length {
            (exponent, T::ONE)
        } else {
            (exponent - poly_length, T::MAX)
        };
        product.decomposed_poly[index] = coefficient;
        fft.forward_as_integer(product.decomposed_poly, product.decomposed_fourier);
        for value in product.decomposed_fourier.iter_mut() {
            value.re -= 1.0;
        }
        add_fourier_product(
            combined.as_mut(),
            positive.as_ref(),
            product.decomposed_fourier,
        );
        if let Some(negative) = negative {
            debug_assert_eq!(negative.as_ref().len(), self.as_ref().len());
            // At roots of unity, conjugation gives R^-1-1 at the same scale.
            for value in product.decomposed_fourier.iter_mut() {
                *value = value.conj();
            }
            add_fourier_product(
                combined.as_mut(),
                negative.as_ref(),
                product.decomposed_fourier,
            );
        }
        combined.external_product_to(input, output, basis, fft, &mut workspace.external_product);
    }
}

/// Adds a shared integer-scale factor product to every Fourier gadget level.
fn add_fourier_product(output: &mut [Complex64], control: &[Complex64], factor: &[Complex64]) {
    for (output, control) in output
        .chunks_exact_mut(factor.len())
        .zip(control.chunks_exact(factor.len()))
    {
        for ((output, &control), &factor) in output.iter_mut().zip(control).zip(factor) {
            *output += control * factor;
        }
    }
}
