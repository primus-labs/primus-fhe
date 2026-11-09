//! Coefficient-domain NTRU to independent LWE key switching with modulus conversion.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::{FheUint, SignedInteger};
use primus_lattice::LweDimension;
use primus_lattice::lwe::Lwe;
use primus_lwe::{LweKeySwitchingKey, LweKeySwitchingParameters, LweSecretKey, LweSecretKeyRef};
use primus_reduce::{Modulus, ModulusSwitch, RingContext};
use primus_shape::PolyLength;

use crate::{NtruCiphertext, NtruSecretKey};

mod batch;
mod evaluator;

use batch::NtruLweKeySwitchingBatchWorkspace;
pub use evaluator::{LweReturnBatchWorkspace, LweReturnEvaluator};

/// Switches a coefficient of `f*c` at modulus Q to an independent LWE key at q.
///
/// Evaluation rounds each NTRU coefficient from Q to q, extracts an LWE under
/// the signed coefficient vector of f, then uses an ordinary LWE key switch at q.
/// The target secret has an independent dimension and need not be NTRU-invertible.
/// No transform table is needed; transformed ciphertexts must first be recovered to
/// coefficients. Source and target share the integer type T (no word-width cast).
/// Both moduli may be native or explicit, including Q = q.
///
/// Bind q once with [`LweReturnEvaluator`] for single coefficients, arbitrary
/// shared-input indices or streams of different NTRUs. Only shared-input returns
/// reuse Q→q conversion; streams convert each source and retain its extracted LWE
/// until the tile is switched.
#[derive(Clone)]
pub struct NtruLweKeySwitchingKey<T: FheUint> {
    input_modulus: Option<T>,
    modulus_switch: ModulusSwitch<T>,
    key_switch: LweKeySwitchingKey<T>,
}

impl<T: FheUint> NtruLweKeySwitchingKey<T> {
    /// Generates LWE encryptions of the gadget-scaled signed coefficients of f at q.
    ///
    /// `input_modulus` fixes Q; `parameters` binds the target domain and basis at q. Secret
    /// coefficients are borrowed directly; no converted copy of f is retained.
    ///
    /// # Panics
    /// Panics before sampling if an explicit Q is below two, a coefficient of f
    /// has magnitude at least an explicit q, or the output key domain or dimensions
    /// violate [`LweKeySwitchingKey::generate`]'s checks. Key storage overflow
    /// also panics.
    ///
    /// # Correctness
    /// Output secret coefficients inherit [`LweKeySwitchingKey::generate`]'s
    /// canonical-residue requirement at q. The input ciphertext must use f and Q;
    /// neither secret identity nor invertibility is checked by this conversion.
    pub fn generate<S, M, R>(
        input_secret_key: &NtruSecretKey<T>,
        input_modulus: S,
        output_secret_key: &LweSecretKey<T>,
        parameters: &LweKeySwitchingParameters<T, M>,
        rng: &mut R,
    ) -> Self
    where
        S: Modulus<ValueT = T>,
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let output_modulus = parameters.output().cipher_modulus();
        let modulus_switch = ModulusSwitch::new(input_modulus, output_modulus);
        if let Some(q) = output_modulus.explicit_value() {
            assert!(
                input_secret_key
                    .as_slice()
                    .iter()
                    .all(|&s| s.unsigned_abs() < q),
                "NTRU secret coefficient magnitude must be less than the target LWE modulus"
            );
        }
        let key_switch = LweKeySwitchingKey::generate(
            LweSecretKeyRef::Signed(input_secret_key.as_slice()),
            output_secret_key,
            parameters,
            rng,
        );
        Self {
            input_modulus: input_modulus.explicit_value(),
            modulus_switch,
            key_switch,
        }
    }

    /// Returns the input NTRU polynomial length and intermediate LWE dimension.
    #[must_use]
    pub fn poly_length(&self) -> usize {
        self.key_switch.input_dimension().get()
    }

    /// Returns Q, or `None` for the native modulus `2^T::BITS`.
    #[must_use]
    pub fn input_modulus(&self) -> Option<T> {
        self.input_modulus
    }

    /// Returns the independent target LWE dimension.
    #[must_use]
    pub fn output_dimension(&self) -> LweDimension {
        self.key_switch.output_dimension()
    }

    /// Returns the target-q key-switch decomposition basis.
    #[must_use]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        self.key_switch.basis()
    }

    /// Returns `[coefficient of f][level][target LWE mask...,body]` storage at q.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        self.key_switch.as_slice()
    }

    /// The public boundary established dimensions/index/modulus. Fuse conversion
    /// and signed extraction into one intermediate LWE for a single return.
    fn key_switch_coefficient<M: RingContext<T>>(
        &self,
        input: NtruCiphertext<&[T]>,
        index: usize,
        mut output: Lwe<&mut [T]>,
        modulus: M,
        mut extracted: Lwe<&mut [T]>,
    ) {
        self.modulus_switch_extract_coefficient(input, index, extracted.as_mut_view(), modulus);
        self.key_switch
            .key_switch_to(&extracted, &mut output, modulus);
    }

    /// Converts canonical Q coefficients directly to the signed q-domain mask.
    /// Single returns and streamed batch preparation share the same rounding order.
    fn modulus_switch_extract_coefficient<M: RingContext<T>>(
        &self,
        input: NtruCiphertext<&[T]>,
        index: usize,
        mut extracted: Lwe<&mut [T]>,
        modulus: M,
    ) {
        let coefficients = input.as_ref();
        let (mask, body) = extracted.a_b_mut();
        *body = T::ZERO;
        let (negative, wrapped) = mask.split_at_mut(index + 1);
        // Switch unsigned coefficients before applying the extraction sign.
        self.modulus_switch.switch_map(
            coefficients[..=index].iter().rev().copied().zip(negative),
            |value, out| *out = modulus.reduce_neg(value),
        );
        self.modulus_switch.switch_map(
            coefficients[index + 1..].iter().rev().copied().zip(wrapped),
            |value, out| *out = value,
        );
    }
}

/// Reusable coefficient workspace for NTRU to LWE conversion.
///
/// Created by [`LweReturnEvaluator::new_scalar_workspace`].
/// Owns one `N+1`-element intermediate LWE at q. It contains only ciphertext
/// coefficients and no secret-key data. Each evaluation overwrites all entries.
pub struct NtruLweKeySwitchingWorkspace<T: FheUint> {
    extracted: Lwe<Box<[T]>>,
}

impl<T: FheUint> NtruLweKeySwitchingWorkspace<T> {
    /// Allocates workspace for an input NTRU polynomial of length N.
    #[must_use]
    fn new(poly_length: PolyLength) -> Self {
        Self {
            extracted: Lwe::zero(poly_length.get()),
        }
    }

    /// Returns the input NTRU polynomial length this workspace supports.
    #[must_use]
    fn poly_length(&self) -> usize {
        self.extracted.dimension()
    }
}
