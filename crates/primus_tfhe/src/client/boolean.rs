use super::{BooleanError, Decryptor, EncryptionKey, Encryptor};
use primus_integer::FheUint;
use primus_lattice::lwe::Lwe;
use primus_lwe::{LweCiphertext, LweSecretKeyRef};
use primus_reduce::RingContext;

/// Encrypts Boolean values under the standard 0/1 encoding modulo 4.
/// Wraps an LWE secret-key or public-key encryptor; public-key noise and identity
/// requirements follow [`EncryptionKey`].
pub struct BooleanEncryptor<'a, T: FheUint, M: RingContext<T>, Key = LweSecretKeyRef<'a, T>> {
    inner: Encryptor<'a, T, M, Key>,
}

impl<'a, T: FheUint, M: RingContext<T>, Key: EncryptionKey<T, M>> BooleanEncryptor<'a, T, M, Key> {
    /// Creates a Boolean encryptor and validates the required plaintext
    /// modulus.
    pub fn try_new(inner: Encryptor<'a, T, M, Key>) -> Result<Self, BooleanError> {
        validate_boolean_modulus(inner.parameters.codec().plaintext_modulus())?;
        Ok(Self { inner })
    }

    /// Encrypts one Boolean value.
    pub fn encrypt<R>(&self, message: bool, rng: &mut R) -> Result<LweCiphertext<T>, BooleanError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let message = if message { T::ONE } else { T::ZERO };
        Ok(self.inner.encrypt_padded(message, rng)?)
    }

    /// Encrypts a Boolean value into existing LWE storage without allocating.
    /// Shares [`Encryptor::encrypt_to`]'s output-dimension and RNG-panic contracts.
    pub fn encrypt_to<R>(
        &self,
        message: bool,
        output: Lwe<&mut [T]>,
        rng: &mut R,
    ) -> Result<(), BooleanError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let message = if message { T::ONE } else { T::ZERO };
        Ok(self.inner.encrypt_padded_to(message, output, rng)?)
    }
}

/// Decrypts ciphertexts using the standard 0/1 Boolean encoding.
pub struct BooleanDecryptor<'a, T: FheUint, M: RingContext<T>> {
    inner: Decryptor<'a, T, M>,
}

impl<'a, T: FheUint, M: RingContext<T>> BooleanDecryptor<'a, T, M> {
    /// Creates a Boolean decryptor and validates the required plaintext
    /// modulus.
    pub fn try_new(inner: Decryptor<'a, T, M>) -> Result<Self, BooleanError> {
        validate_boolean_modulus(inner.decoder.plaintext_modulus())?;
        Ok(Self { inner })
    }

    /// Decrypts one Boolean ciphertext.
    ///
    /// Uses rounded encoding modulo 4 and rejects decoded values other than 0/1.
    /// The raw ciphertext must satisfy [`Decryptor::decrypt_phase`]'s key,
    /// modulus and canonical-coefficient requirements.
    pub fn decrypt(&self, ciphertext: Lwe<&[T]>) -> Result<bool, BooleanError> {
        let message = self.inner.decrypt(ciphertext)?;
        if message == T::ZERO {
            Ok(false)
        } else if message == T::ONE {
            Ok(true)
        } else {
            Err(BooleanError::InvalidPlaintext)
        }
    }
}

fn validate_boolean_modulus<T: FheUint>(modulus: T) -> Result<(), BooleanError> {
    if modulus == T::ONE << crate::BOOLEAN_PLAINTEXT_BITS {
        Ok(())
    } else {
        Err(BooleanError::PlaintextModulusMustBeFour)
    }
}
