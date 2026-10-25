//! Batch encryption of constant polynomials into Fourier GGSWs.

use super::{FourierGlweGadgetEncryptWorkspace, FourierGlweSecretKey};
use crate::{FourierGgswCiphertext, GlevParameters};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::ggsw::Ggsw;
use primus_modulus::NativeModulus;

impl FourierGlweSecretKey {
    /// Encrypts native-ring constants into consecutive Fourier GGSWs.
    ///
    /// Each input is a constant polynomial, scaled by the gadget basis without
    /// plaintext encoding. Output uses `[input][row][level][component][Fourier
    /// coefficient]` layout, with exactly `input.len() * params.fourier_ggsw_len()`
    /// entries. Output and scratch are reused without allocating; shared
    /// resources are checked once. Adjacent equal constants reuse prepared level
    /// transforms, so preparation time depends on the input sequence. Empty
    /// input/output consumes no randomness.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes on incompatible key, FFT, workspace or
    /// output lengths, or a batch length overflow. RNG/FFT panics can leave
    /// partial output and modified scratch.
    ///
    /// # Correctness
    ///
    /// Use the FFT table instance with which this secret key was constructed.
    pub fn encrypt_ggsw_constant_batch_to<T, Table, R>(
        &self,
        input: &[T],
        output: &mut [Complex64],
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierGlweGadgetEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        self.assert_gadget_compatible(params, fft);
        workspace.assert_ggsw_compatible(params.size());
        let ggsw_len = params.fourier_ggsw_len();
        let expected = input
            .len()
            .checked_mul(ggsw_len)
            .expect("Fourier GGSW batch length overflow");
        assert_eq!(
            output.len(),
            expected,
            "Fourier GGSW batch output layout mismatch"
        );

        workspace.encoded.as_mut().fill(T::ZERO);
        let mut previous = None;
        for (&constant, block) in input.iter().zip(output.chunks_exact_mut(ggsw_len)) {
            if previous != Some(constant) {
                prepare_constant_levels(constant, params, fft, workspace);
                previous = Some(constant);
            }
            self.encrypt_ggsw_from_levels_to(
                FourierGgswCiphertext::new(block),
                params,
                fft,
                rng,
                workspace,
            );
        }
    }

    /// Encrypts native-ring constants into consecutive coefficient GGSWs.
    ///
    /// Uses the same Fourier encryption and inverse transform as
    /// [`Self::encrypt_ggsw_constant_batch_to`] followed by `write_torus_form`.
    /// Output layout is `[input][row][level][component][coefficient]`, with
    /// `input.len() * params.ggsw_len()` entries. Reuses one Fourier GGSW in
    /// `fourier_scratch` and the gadget workspace without allocating. Adjacent
    /// equal constants reuse prepared levels, as in the Fourier-output batch.
    /// Empty input/output consumes no randomness after resource validation.
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::encrypt_ggsw_constant_batch_to`]'s FFT table requirement.
    /// Inverse conversion can incur floating-point rounding error.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes on incompatible key, FFT, workspace,
    /// output length or length overflow. `fourier_scratch` must contain exactly
    /// `params.fourier_ggsw_len()` elements. RNG/FFT panics can leave partial
    /// output and modified scratch.
    #[allow(clippy::too_many_arguments)] // Separate reusable coefficient/Fourier buffers.
    pub fn encrypt_ggsw_constant_batch_coeff_to<T, Table, R>(
        &self,
        input: &[T],
        output: &mut [T],
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierGlweGadgetEncryptWorkspace<T>,
        fourier_scratch: &mut [Complex64],
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        self.assert_gadget_compatible(params, fft);
        workspace.assert_ggsw_compatible(params.size());
        let ggsw_len = params.ggsw_len();
        let expected = input
            .len()
            .checked_mul(ggsw_len)
            .expect("coefficient GGSW batch length overflow");
        assert_eq!(
            output.len(),
            expected,
            "coefficient GGSW batch output layout mismatch"
        );
        assert_eq!(
            fourier_scratch.len(),
            params.fourier_ggsw_len(),
            "Fourier GGSW scratch layout mismatch"
        );

        let mut transformed = FourierGgswCiphertext::new(fourier_scratch);
        workspace.encoded.as_mut().fill(T::ZERO);
        let mut previous = None;
        for (&constant, block) in input.iter().zip(output.chunks_exact_mut(ggsw_len)) {
            if previous != Some(constant) {
                prepare_constant_levels(constant, params, fft, workspace);
                previous = Some(constant);
            }
            self.encrypt_ggsw_from_levels_to(
                transformed.as_mut_view(),
                params,
                fft,
                rng,
                workspace,
            );
            transformed.write_torus_form(&mut Ggsw::new(block), fft);
        }
    }
}

// Keep the original per-level torus lifting and FFT arithmetic. Only consecutive
// equal constants within one batch reuse these transforms: no cache survives a
// change of basis, table, or an intervening nonconstant encryption. The batch
// wrapper has cleared encoded's tail and validated the workspace.
fn prepare_constant_levels<T: TorusFftValue, Table: FftTable>(
    constant: T,
    params: &GlevParameters<T, NativeModulus<T>>,
    fft: &mut FftEngine<'_, Table>,
    workspace: &mut FourierGlweGadgetEncryptWorkspace<T>,
) {
    for (scalar, transformed) in params.basis().scalar_iter().zip(
        workspace
            .level_transforms
            .chunks_exact_mut(fft.fourier_length()),
    ) {
        workspace.encoded.as_mut()[0] = constant.wrapping_mul(scalar);
        fft.forward_as_torus(workspace.encoded.as_ref(), transformed);
    }
}
