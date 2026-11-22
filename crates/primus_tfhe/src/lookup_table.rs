//! Lookup-table representations and their construction APIs.
//!
//! - `single`: one output; front-half and odd full-domain constructors.
//! - `interleaved`: multiple output lanes sharing one blind rotation.
//! - `circuit_bootstrap`: a single integer function at all CBS gadget scales.
//! - `factorized`: a common polynomial and fixed-scale difference factors for MVB.
//! - `bivariate`: bounded input packing followed by a single-output lookup.
//! - `compile`: input geometry, validation and polynomial filling.
//! - `compiler`: shared plaintext-output constructors using rounded codecs.

mod bivariate;
mod circuit_bootstrap;
mod compile;
mod compiler;
mod factorized;
mod interleaved;
mod single;

use primus_integer::FheUint;

pub use bivariate::BivariateLookupTable;
pub use circuit_bootstrap::{CbsInputEncoding, CircuitBootstrapLookupTable};
pub use compile::front_half_domain_len;
pub use compiler::LookupTableCompiler;
pub use factorized::FactorizedLookupTable;
pub use interleaved::InterleavedLookupTable;
pub use single::LookupTable;

// Input encoding determines rotation centers. The coefficient modulus is shared
// by the LUT polynomial and accumulator; output scale is independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LookupTableEncoding<T: FheUint> {
    input_plaintext_modulus: T,
    input_ciphertext_modulus: Option<T>,
    coefficient_modulus: Option<T>,
}

impl<T: FheUint> LookupTableEncoding<T> {
    fn is_compatible(
        &self,
        input_plaintext_modulus: T,
        input_ciphertext_modulus: Option<T>,
        coefficient_modulus: Option<T>,
    ) -> bool {
        self.input_plaintext_modulus == input_plaintext_modulus
            && self.matches_ciphertext_moduli(input_ciphertext_modulus, coefficient_modulus)
    }

    /// Compares q and Q when a raw operation takes the input encoding from the LUT.
    fn matches_ciphertext_moduli(
        &self,
        input_ciphertext_modulus: Option<T>,
        coefficient_modulus: Option<T>,
    ) -> bool {
        self.input_ciphertext_modulus == input_ciphertext_modulus
            && self.coefficient_modulus == coefficient_modulus
    }
}
