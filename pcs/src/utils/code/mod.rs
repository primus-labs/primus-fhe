mod expander;
mod reedsolomon;

pub use expander::{ExpanderCode, ExpanderCodeSpec};
use rand::{CryptoRng, Rng};
pub use reedsolomon::ReedSolomonCode;

/// LinearCode
pub trait LinearCode<F>: Sync + Send + Default + Clone {
    /// return the message length of the code
    fn message_len(&self) -> usize;

    /// return the codeword length of the code
    fn codeword_len(&self) -> usize;

    /// return the relative distance of the code
    fn distance(&self) -> f64;

    /// return the proximity gap of the code
    fn proximity_gap(&self) -> f64 {
        1.0 / 3.0
    }

    /// store the message in target[..message_len] with target[message_len..] keeping clean (all zero)
    /// encode the message into the codeword and store the codeword in target[..codeword_len]
    /// normally tagert.len() == codeword_len
    fn encode(&self, target: &mut [F]);
}

/// Code Spec
pub trait LinearCodeSpec<F>: Sync + Send + Default {
    /// Linear Code
    type Code: LinearCode<F>;
    /// generate LinearCode
    fn code(&self, message_ln: usize, codeword_len: usize, rng: impl Rng + CryptoRng)
        -> Self::Code;
}
