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
    ModulusSwitchBeforeBlindRotation, Parameters, Steps,
};

pub use ciphertext::{
    LWECiphertext, NTRUCiphertext, NTTNTRUCiphertext, NTTRLWECiphertext, RLWECiphertext,
};
pub use plaintext::{decode, encode, LWEModulusType, LWEMsgType};

pub use secret_key::{
    LWESecretKeyType, NTTRingSecretKey, RingSecretKey, RingSecretKeyType, SecretKeyPack,
};

pub use blind_rotation::{NTRUBlindRotationKey, RLWEBlindRotationKey};
pub use key_switch::{KeySwitchingKeyEnum, KeySwitchingLWEKey, KeySwitchingRLWEKey};

pub use modulus_switch::{
    lwe_modulus_switch, lwe_modulus_switch_between_modulus_inplace, lwe_modulus_switch_inplace,
    ModulusSwitchRoundMethod,
};
