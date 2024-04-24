use crate::{bootstrapping::BootstrappingKey, Ciphertext, KeySwitchKey, Plaintext};

pub trait SecretKey<P: Plaintext, C: Ciphertext> {
    fn encrypt(&self, plaintext: P) -> C;

    fn decrypt(&self, ciphertext: C) -> P;
}

pub trait BootstrappingKeyGeneration<I: Ciphertext, B: BootstrappingKey<I, O>, O: Ciphertext> {
    fn generate_bootstrapping_key(&self) -> B;
}

pub trait KeySwitchKeyGeneration<I: Ciphertext, KS: KeySwitchKey<I, O>, O: Ciphertext> {
    fn generate_key_switching_key(&self) -> KS;
}
