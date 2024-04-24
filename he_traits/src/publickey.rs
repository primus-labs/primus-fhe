use crate::{Ciphertext, Plaintext};

pub trait PublicKey<P: Plaintext, C: Ciphertext> {
    fn encrypt(&self, plaintext: P) -> C;
}
