mod error;

mod parameter;

mod ciphertext;
mod plaintext;

mod secret_key;

pub use error::FHEError;

pub use parameter::{ConstParameters, Parameters, ParametersBuilder};

pub use ciphertext::{LWECiphertext, NTRUCiphertext, NTTNTRUCiphertext};
pub use plaintext::{decode, encode, LWEContainer, LWEPlaintext};

pub use secret_key::{LWESecretKey, NTRUSecretKey, NTTNTRUSecretKey, SecretKeyPack, SecretKeyType};
