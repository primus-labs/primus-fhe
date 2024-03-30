pub mod brakedown;
pub use brakedown::*;

pub trait LinearCode<F>: Sync + Send {
    fn message_len(&self) -> usize;

    fn codeword_len(&self) -> usize;

    fn encode(&self, input: impl AsMut<[F]>);
}