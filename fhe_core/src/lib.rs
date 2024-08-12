#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Implementations of FHE core operations.

mod error;

mod parameter;

mod ciphertext;
mod plaintext;

mod secret_key;

mod blind_rotation;
mod key_switch;

mod modulus_switch;
pub mod utils;

pub use error::FHECoreError;

pub use parameter::{
    BlindRotationType, ConstParameters, DefaultExtendsionFieldU32x4, DefaultFieldU32, DefaultQks,
    Parameters, StepsAfterBR,
};

pub use ciphertext::{
    LWECiphertext, NTRUCiphertext, NTTNTRUCiphertext, NTTRLWECiphertext, RLWECiphertext,
};
pub use plaintext::{decode, encode, LWEModulusType, LWEMsgType};

pub use secret_key::{RingSecretKeyType, SecretKeyPack, SecretKeyType};

pub use blind_rotation::{NTRUBlindRotationKey, RLWEBlindRotationKey};
pub use key_switch::{EitherKeySwitchingKey, KeySwitchingKey};

pub use modulus_switch::{
    lwe_modulus_switch, lwe_modulus_switch_between_field, lwe_modulus_switch_inplace,
    rlwe_modulus_switch_between_field, ModulusSwitchRoundMethod,
};
