use crate::Ciphertext;

pub trait BootstrappingKey<I: Ciphertext, O: Ciphertext> {
    fn bootstrapping(&self, input: I) -> O;
}
