pub trait Message: Eq {}

pub trait Plaintext {}

pub trait Code<M: Message, P: Plaintext> {
    fn encode(message: M) -> P;

    fn decode(plaintext: P) -> M;
}
