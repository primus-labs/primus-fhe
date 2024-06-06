mod brakedown;
mod reedsolomon;

pub use brakedown::{BrakedownCode, BrakedownCodeSpec};
pub use reedsolomon::ReedSolomonCode;

/// LinearCode
pub trait LinearCode<F>: Sync + Send + Default {
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
    fn encode(&self, target: impl AsMut<[F]>);
}
