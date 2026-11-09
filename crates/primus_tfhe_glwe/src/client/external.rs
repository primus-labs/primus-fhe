//! Client-side selection of the external q/Q domain, once per operation.
use primus_integer::FheUint;
use primus_lwe::{LweCiphertext, LweSecretKeyRef};
use primus_reduce::RingContext;
use primus_tfhe::{BooleanError, ClientError, EncryptionKey, Lwe};

/// A client bound to the external secret's domain for the selected PBS order.
/// Dispatch occurs once per message, outside all coefficient loops. No extra
/// secret, sampler or ciphertext storage is owned by this selection.
pub enum ExternalLweClient<Small, Ring> {
    /// BR→KS uses the small LWE secret and modulus q.
    Small(Small),
    /// KS→BR uses the flattened ring secret and modulus Q.
    Ring(Ring),
}

/// Rounded encryptor bound to the order's external domain.
pub type Encryptor<'a, T, M, Key = LweSecretKeyRef<'a, T>, LM = M> = ExternalLweClient<
    primus_tfhe::Encryptor<'a, T, LM, Key>,
    primus_tfhe::Encryptor<'a, T, M, Key>,
>;
/// Rounded or Scaled decryptor bound to the order's external domain.
pub type Decryptor<'a, T, M, LM = M> =
    ExternalLweClient<primus_tfhe::Decryptor<'a, T, LM>, primus_tfhe::Decryptor<'a, T, M>>;
/// Boolean encryptor in the selected external domain, with plaintext modulus four.
pub type BooleanEncryptor<'a, T, M, Key = LweSecretKeyRef<'a, T>, LM = M> = ExternalLweClient<
    primus_tfhe::BooleanEncryptor<'a, T, LM, Key>,
    primus_tfhe::BooleanEncryptor<'a, T, M, Key>,
>;
/// Boolean decryptor in the selected external domain.
pub type BooleanDecryptor<'a, T, M, LM = M> = ExternalLweClient<
    primus_tfhe::BooleanDecryptor<'a, T, LM>,
    primus_tfhe::BooleanDecryptor<'a, T, M>,
>;

impl<'a, T: FheUint, M: RingContext<T>, LM: RingContext<T>, Key> Encryptor<'a, T, M, Key, LM>
where
    Key: EncryptionKey<T, M> + EncryptionKey<T, LM>,
{
    /// Uses the bound domain; inherits [`primus_tfhe::Encryptor::encrypt`]'s message and noise contracts.
    pub fn encrypt<R: rand::Rng + rand::CryptoRng>(
        &self,
        message: T,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, ClientError> {
        match self {
            Self::Small(client) => client.encrypt(message, rng),
            Self::Ring(client) => client.encrypt(message, rng),
        }
    }

    /// Uses the bound domain; inherits [`primus_tfhe::Encryptor::encrypt_padded`]'s message and noise contracts.
    pub fn encrypt_padded<R: rand::Rng + rand::CryptoRng>(
        &self,
        message: T,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, ClientError> {
        match self {
            Self::Small(client) => client.encrypt_padded(message, rng),
            Self::Ring(client) => client.encrypt_padded(message, rng),
        }
    }

    /// Uses the bound domain; inherits [`primus_tfhe::Encryptor::encrypt_centered`]'s message and noise contracts.
    pub fn encrypt_centered<R: rand::Rng + rand::CryptoRng>(
        &self,
        message: T,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, ClientError> {
        match self {
            Self::Small(client) => client.encrypt_centered(message, rng),
            Self::Ring(client) => client.encrypt_centered(message, rng),
        }
    }

    /// Reuses output storage; inherits [`primus_tfhe::Encryptor::encrypt_to`]'s contracts.
    pub fn encrypt_to<R: rand::Rng + rand::CryptoRng>(
        &self,
        message: T,
        output: Lwe<&mut [T]>,
        rng: &mut R,
    ) -> Result<(), ClientError> {
        match self {
            Self::Small(client) => client.encrypt_to(message, output, rng),
            Self::Ring(client) => client.encrypt_to(message, output, rng),
        }
    }

    /// Reuses output storage; inherits [`primus_tfhe::Encryptor::encrypt_padded_to`]'s contracts.
    pub fn encrypt_padded_to<R: rand::Rng + rand::CryptoRng>(
        &self,
        message: T,
        output: Lwe<&mut [T]>,
        rng: &mut R,
    ) -> Result<(), ClientError> {
        match self {
            Self::Small(client) => client.encrypt_padded_to(message, output, rng),
            Self::Ring(client) => client.encrypt_padded_to(message, output, rng),
        }
    }

    /// Reuses output storage; inherits [`primus_tfhe::Encryptor::encrypt_centered_to`]'s contracts.
    pub fn encrypt_centered_to<R: rand::Rng + rand::CryptoRng>(
        &self,
        message: T,
        output: Lwe<&mut [T]>,
        rng: &mut R,
    ) -> Result<(), ClientError> {
        match self {
            Self::Small(client) => client.encrypt_centered_to(message, output, rng),
            Self::Ring(client) => client.encrypt_centered_to(message, output, rng),
        }
    }
}

impl<'a, T: FheUint, M: RingContext<T>, LM: RingContext<T>> Decryptor<'a, T, M, LM> {
    /// Uses the bound external domain; inherits [`primus_tfhe::Decryptor::decrypt`]'s contracts.
    pub fn decrypt(&self, ciphertext: Lwe<&[T]>) -> Result<T, ClientError> {
        match self {
            Self::Small(client) => client.decrypt(ciphertext),
            Self::Ring(client) => client.decrypt(ciphertext),
        }
    }

    /// Uses the bound external domain; inherits [`primus_tfhe::Decryptor::decrypt_phase`]'s contracts.
    pub fn decrypt_phase(&self, ciphertext: Lwe<&[T]>) -> Result<T, ClientError> {
        match self {
            Self::Small(client) => client.decrypt_phase(ciphertext),
            Self::Ring(client) => client.decrypt_phase(ciphertext),
        }
    }
}

impl<'a, T: FheUint, M: RingContext<T>, LM: RingContext<T>, Key> BooleanEncryptor<'a, T, M, Key, LM>
where
    Key: EncryptionKey<T, M> + EncryptionKey<T, LM>,
{
    /// Checks that the prepared external encryptor uses plaintext modulus four.
    pub fn try_new(inner: Encryptor<'a, T, M, Key, LM>) -> Result<Self, BooleanError> {
        Ok(match inner {
            ExternalLweClient::Small(client) => {
                Self::Small(primus_tfhe::BooleanEncryptor::try_new(client)?)
            }
            ExternalLweClient::Ring(client) => {
                Self::Ring(primus_tfhe::BooleanEncryptor::try_new(client)?)
            }
        })
    }

    /// Encrypts a Boolean with the selected external secret and modulus.
    pub fn encrypt<R: rand::Rng + rand::CryptoRng>(
        &self,
        message: bool,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, BooleanError> {
        match self {
            Self::Small(client) => client.encrypt(message, rng),
            Self::Ring(client) => client.encrypt(message, rng),
        }
    }

    /// Encrypts a Boolean into existing storage; inherits the underlying client's contracts.
    pub fn encrypt_to<R: rand::Rng + rand::CryptoRng>(
        &self,
        message: bool,
        output: Lwe<&mut [T]>,
        rng: &mut R,
    ) -> Result<(), BooleanError> {
        match self {
            Self::Small(client) => client.encrypt_to(message, output, rng),
            Self::Ring(client) => client.encrypt_to(message, output, rng),
        }
    }
}

impl<'a, T: FheUint, M: RingContext<T>, LM: RingContext<T>> BooleanDecryptor<'a, T, M, LM> {
    /// Checks that the prepared external decryptor uses plaintext modulus four.
    pub fn try_new(inner: Decryptor<'a, T, M, LM>) -> Result<Self, BooleanError> {
        Ok(match inner {
            ExternalLweClient::Small(client) => {
                Self::Small(primus_tfhe::BooleanDecryptor::try_new(client)?)
            }
            ExternalLweClient::Ring(client) => {
                Self::Ring(primus_tfhe::BooleanDecryptor::try_new(client)?)
            }
        })
    }

    /// Decodes a Boolean; inherits the underlying client's canonical-input and noise contracts.
    pub fn decrypt(&self, input: Lwe<&[T]>) -> Result<bool, BooleanError> {
        match self {
            Self::Small(client) => client.decrypt(input),
            Self::Ring(client) => client.decrypt(input),
        }
    }
}
