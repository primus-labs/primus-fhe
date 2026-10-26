//! Split Fourier trace with exact coefficient key generation.
mod automorphism;

use primus_data::Data;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_lattice::glwe::Glwe;
use primus_modulus::NativeModulus;

use crate::secret_key::exact::ExactSecretProduct;
use automorphism::{SplitGlweAutomorphismKey, SplitGlweAutomorphismWorkspace};

use crate::{GlevParameters, GlweSecretKey, GlweSize};

/// Split(35) native-u64 trace keys for rank-one binary/ternary ring secrets.
///
/// Each exact coefficient key is converted as unsigned low35/high29, both in
/// 2^-64 torus units. Digit FFTs are shared; products and inverse rounding are
/// separate, then wrapping reconstruction restores the original scale. This
/// doubles trace key payload and inverse transforms; it is a precision option.
/// It does not change gadget decomposition, noise, trace normalization or SS.
/// The generic torus word does not imply support for other widths:
/// [`Self::generate`] rejects non-64-bit words before sampling.
#[derive(Clone)]
pub struct SplitFourierGlweTraceKey<T: TorusFftValue> {
    keys: Vec<SplitGlweAutomorphismKey>,
    size: GlweSize,
    basis: ApproxSignedBasis<T>,
}

/// Buffers allocated only for the selected split trace representation.
/// Obtain matching scratch from [`SplitFourierGlweTraceKey::new_workspace`].
pub struct SplitFourierGlweTraceWorkspace<T: TorusFftValue> {
    output: Glwe<Vec<T>>,
    automorphism: SplitGlweAutomorphismWorkspace<T>,
}
impl<T: TorusFftValue> SplitFourierGlweTraceKey<T> {
    /// Generates exact coefficient keys using auxiliary NTT/centered CRT and
    /// retains only their split Fourier spectra. Auxiliary moduli do not change
    /// the native ciphertext modulus. No ordinary Fourier key is generated.
    ///
    /// # Panics
    /// Panics before sampling unless T has 64 bits, rank is one, all secret
    /// coefficients are in {-1,0,1}, and secret/parameter/FFT lengths agree.
    ///
    /// # Correctness
    /// Subsequent evaluation must use this FFT table instance; equal lengths
    /// alone do not establish the spectrum representation. This option reduces
    /// Fourier error, but does not certify the complete request's noise margin.
    #[must_use]
    pub fn generate<Table: FftTable, R: rand::Rng + rand::CryptoRng>(
        secret: &GlweSecretKey<T>,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> Self {
        let size = parameters.glwe_size();
        assert_eq!(T::BITS, 64, "split35 requires a 64-bit native torus");
        assert_eq!(size.dimension().get(), 1, "split35 requires GLWE rank one");
        assert_eq!(
            secret.glwe_size(),
            size,
            "split trace secret layout mismatch"
        );
        assert_eq!(
            fft.poly_length(),
            size.poly_length(),
            "split trace FFT length mismatch"
        );
        let mut product = ExactSecretProduct::try_new(secret, T::ONE)
            .expect("split35 requires secret coefficients in -1..=1");
        let keys = (1..=size.poly_length().log_n())
            .rev()
            .map(|shift| {
                SplitGlweAutomorphismKey::generate(
                    (1 << shift) + 1,
                    secret,
                    parameters,
                    &mut product,
                    fft,
                    rng,
                )
            })
            .collect();
        Self {
            keys,
            size,
            basis: parameters.basis().clone(),
        }
    }

    /// Returns the exact decomposition basis retained during generation.
    #[must_use]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Allocates only the buffers required by this key's split representation.
    #[must_use]
    pub fn new_workspace(&self) -> SplitFourierGlweTraceWorkspace<T> {
        SplitFourierGlweTraceWorkspace {
            output: Glwe::zero(self.size.glwe_len()),
            automorphism: SplitGlweAutomorphismWorkspace::new(self.size),
        }
    }

    /// Projects coefficients 0..count into consecutive constant-message GLWEs.
    /// No zero message tail is required; output is overwritten without allocation.
    /// Reverse trace uses degrees 3,5,...,N+1 and unsigned floor(x/2) at each
    /// step, including wrapped negatives. Error may remain at every coefficient.
    ///
    /// # Correctness
    /// Inherits [`Self::generate`]'s FFT identity and noise requirements. Input
    /// must be under the generating native ring secret.
    ///
    /// # Panics
    /// Panics before writes if count>N, output is not count complete GLWEs,
    /// or input/FFT/workspace lengths disagree. Count zero requires empty output.
    pub fn project_prefix_coefficients_to<Table: FftTable, A: Data<Elem = T>>(
        &self,
        input: &Glwe<A>,
        count: usize,
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut SplitFourierGlweTraceWorkspace<T>,
    ) {
        assert!(
            count <= self.size.poly_length().get(),
            "projection prefix exceeds polynomial length"
        );
        assert_eq!(
            input.as_ref().len(),
            self.size.glwe_len(),
            "projection input layout mismatch"
        );
        assert_eq!(
            output.len(),
            count
                .checked_mul(self.size.glwe_len())
                .expect("projection output length overflow"),
            "projection output layout mismatch"
        );
        assert_eq!(
            fft.poly_length(),
            self.size.poly_length(),
            "split trace FFT length mismatch"
        );
        assert_eq!(
            workspace.output.as_ref().len(),
            self.size.glwe_len(),
            "split trace workspace length mismatch"
        );
        let modulus = NativeModulus::new();
        super::kernels::project_to(
            input.as_view(),
            0..count,
            output,
            self.size,
            modulus,
            |out| {
                super::kernels::trace_assign::<_, _, _, _, true>(
                    out,
                    self.keys.len(),
                    workspace.output.as_mut(),
                    modulus,
                    |values| {
                        for v in values {
                            *v >>= 1u32;
                        }
                    },
                    |index, input, output| {
                        self.keys[index].apply_kernel_to(
                            &self.basis,
                            Glwe::new(input),
                            Glwe::new(output),
                            fft,
                            &mut workspace.automorphism,
                        )
                    },
                );
            },
        );
    }
}
