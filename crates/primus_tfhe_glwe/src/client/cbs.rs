//! CBS input clients keep the encoding choice out of individual encryption calls.
use super::Encryptor;
use primus_integer::FheUint;
use primus_lwe::{LweCiphertext, LweSecretKeyRef};
use primus_reduce::RingContext;
use primus_tfhe::{CbsInputEncoding, ClientError, EncryptionKey, Lwe};

/// Encrypts the input domain of one prepared CBS operation.
/// Padded accepts `0..ceil(t/2)`; MSB Boolean accepts `0..2` and encodes at half
/// the external ciphertext modulus. Neither changes ordinary PBS's encoding.
/// Borrows the external secret/public key and fresh noise sampler; owns no scratch.
pub struct CbsEncryptor<
    'a,
    T: FheUint,
    M: RingContext<T>,
    Key = LweSecretKeyRef<'a, T>,
    LM: RingContext<T> = M,
> {
    encryptor: Encryptor<'a, T, M, Key, LM>,
    encoding: CbsInputEncoding,
}

impl<'a, T: FheUint, M: RingContext<T>, LM: RingContext<T>, Key> CbsEncryptor<'a, T, M, Key, LM>
where
    Key: EncryptionKey<T, M> + EncryptionKey<T, LM>,
{
    pub(super) fn new(encryptor: Encryptor<'a, T, M, Key, LM>, encoding: CbsInputEncoding) -> Self {
        Self {
            encryptor,
            encoding,
        }
    }

    /// Encrypts a message in the bound CBS input domain, rejecting out-of-range
    /// values. Fresh encryption correctness alone does not establish the CBS
    /// rotation/trace/scheme-switch noise budget.
    pub fn encrypt<R: rand::Rng + rand::CryptoRng>(
        &self,
        message: T,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, ClientError> {
        match self.encoding {
            CbsInputEncoding::Padded => self.encryptor.encrypt_padded(message, rng),
            CbsInputEncoding::MsbBoolean => self.encryptor.encrypt(message, rng),
        }
    }

    /// Reuses output storage; rejects a message outside the bound CBS input
    /// domain or an incorrect output dimension before writing.
    /// Inherits [`Self::encrypt`]'s noise contract.
    pub fn encrypt_to<R: rand::Rng + rand::CryptoRng>(
        &self,
        message: T,
        output: Lwe<&mut [T]>,
        rng: &mut R,
    ) -> Result<(), ClientError> {
        match self.encoding {
            CbsInputEncoding::Padded => self.encryptor.encrypt_padded_to(message, output, rng),
            CbsInputEncoding::MsbBoolean => self.encryptor.encrypt_to(message, output, rng),
        }
    }
}
