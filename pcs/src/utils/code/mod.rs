mod expander;
mod reedsolomon;

pub use expander::{ExpanderCode, ExpanderCodeSpec};
use rand::{CryptoRng, Rng};
pub use reedsolomon::ReedSolomonCode;

/// Define the trait of linear code
pub trait LinearCode<F>: Sync + Send + Default + Clone {
    /// Return the message length of the code
    fn message_len(&self) -> usize;

    /// Return the codeword length of the code
    fn codeword_len(&self) -> usize;

    /// Return the relative distance of the code
    fn distance(&self) -> f64;

    /// Return the proximity gap of the code
    fn proximity_gap(&self) -> f64 {
        1.0 / 3.0
    }

    /// Encode the message into the target.
    /// Store the message in target[..message_len] with target[message_len..].
    /// Encode the message into the codeword and store the codeword in target.
    fn encode(&self, target: &mut [F]);
}

/// Define the trait of linear code specification.
pub trait LinearCodeSpec<F>: Sync + Send + Default {
    /// The type of linear code
    type Code: LinearCode<F>;
    /// Generate the instance of linear code
    fn code(&self, message_ln: usize, rng: &mut (impl Rng + CryptoRng)) -> Self::Code;
}
