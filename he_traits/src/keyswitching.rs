use crate::Ciphertext;

pub trait KeySwitchKey<I: Ciphertext, O: Ciphertext> {
    fn key_switch(&self, input: I) -> O;
}
