mod brakedown;
mod reedsolomon;

pub use brakedown::{BrakedownCode, BrakedownCodeSpec};
pub use reedsolomon::ReedSolomonCode;

/// LinearCode
pub trait LinearCode<F>: Sync + Send {
    /// return the message length of the code
    fn message_len(&self) -> usize;

    /// return the codeword length of the code
    fn codeword_len(&self) -> usize;

    /// store the message in target[..message_len] with target[message_len..] keeping clean (all zero)
    /// encode the message into the codeword and store the codeword in target[..codeword_len]
    /// normally tagert.len() == codeword_len
    fn encode(&self, target: impl AsMut<[F]>);
}
