use primus_integer::FheUint;
use primus_lattice::lwe::Lwe;
use primus_lwe::{LweCiphertext, LwePublicKey, LweSecretKeyRef};
use primus_reduce::RingContext;

use super::{ClientError, LweClientParameters};

/// Encrypts encoded LWE residues using a borrowed secret or public key.
///
/// This interface only selects the encryption kernel; message checks and encoding
/// belong to [`super::Encryptor`]. Implementations must use the supplied domain
/// and samplers and overwrite outputs without allocating.
///
/// A public key must come from the external secret paired with the server key;
/// dimension and modulus checks do not establish key identity. Fresh public
/// encryption uses the external secret-encryption noise sampler; combined noise
/// must satisfy [`LwePublicKey`]'s requirements and the PBS/ManyLUT input budget.
pub trait EncryptionKey<T: FheUint, M: RingContext<T>> {
    /// Checks the LWE dimension and, for public keys, the ciphertext modulus.
    /// Raw secret views cannot check a modulus; bind their owning key first.
    fn check_compatible(
        &self,
        parameters: &LweClientParameters<'_, T, M>,
    ) -> Result<(), ClientError>;

    /// Allocates an encryption of an encoded residue in `[0, q)`.
    ///
    /// # Correctness
    /// Requires successful [`Self::check_compatible`], the parameter view's
    /// sampler contracts and the key's identity, noise and coefficient ranges.
    /// No plaintext scaling occurs here.
    #[must_use]
    fn encrypt_encoded<R: rand::Rng + rand::CryptoRng>(
        &self,
        plaintext: T,
        parameters: &LweClientParameters<'_, T, M>,
        rng: &mut R,
    ) -> LweCiphertext<T>;

    /// Overwrites existing LWE storage without allocating.
    ///
    /// # Correctness
    /// Inherits [`Self::encrypt_encoded`]'s residue, parameter and key contracts.
    ///
    /// # Panics
    /// Output must have the key's LWE dimension. RNG panics may leave partial
    /// output; see [`LweSecretKeyRef::encrypt_encoded_to`] and
    /// [`LwePublicKey::encrypt_encoded_to`].
    fn encrypt_encoded_to<R: rand::Rng + rand::CryptoRng>(
        &self,
        plaintext: T,
        output: Lwe<&mut [T]>,
        parameters: &LweClientParameters<'_, T, M>,
        rng: &mut R,
    );
}

impl<T: FheUint, M: RingContext<T>> EncryptionKey<T, M> for LweSecretKeyRef<'_, T> {
    fn check_compatible(
        &self,
        parameters: &LweClientParameters<'_, T, M>,
    ) -> Result<(), ClientError> {
        check_dimension(parameters.dimension().get(), self.dimension())
    }

    fn encrypt_encoded<R: rand::Rng + rand::CryptoRng>(
        &self,
        plaintext: T,
        parameters: &LweClientParameters<'_, T, M>,
        rng: &mut R,
    ) -> LweCiphertext<T> {
        // Keep the secret-key path's direct initialization of spare capacity.
        (*self).encrypt_encoded(
            plaintext,
            parameters.codec().ciphertext_modulus(),
            parameters.uniform(),
            parameters.noise(),
            rng,
        )
    }

    fn encrypt_encoded_to<R: rand::Rng + rand::CryptoRng>(
        &self,
        plaintext: T,
        mut output: Lwe<&mut [T]>,
        parameters: &LweClientParameters<'_, T, M>,
        rng: &mut R,
    ) {
        (*self).encrypt_encoded_to(
            plaintext,
            &mut output,
            parameters.codec().ciphertext_modulus(),
            parameters.uniform(),
            parameters.noise(),
            rng,
        );
    }
}

impl<T: FheUint, M: RingContext<T>> EncryptionKey<T, M> for &LwePublicKey<T> {
    fn check_compatible(
        &self,
        parameters: &LweClientParameters<'_, T, M>,
    ) -> Result<(), ClientError> {
        check_dimension(parameters.dimension().get(), self.dimension().get())?;
        if self.cipher_modulus_minus_one() != parameters.codec().ciphertext_modulus().minus_one() {
            return Err(ClientError::PublicKeyModulusMismatch);
        }
        Ok(())
    }

    fn encrypt_encoded<R: rand::Rng + rand::CryptoRng>(
        &self,
        plaintext: T,
        parameters: &LweClientParameters<'_, T, M>,
        rng: &mut R,
    ) -> LweCiphertext<T> {
        LwePublicKey::encrypt_encoded(
            self,
            plaintext,
            parameters.codec().ciphertext_modulus(),
            parameters.noise(),
            rng,
        )
    }

    fn encrypt_encoded_to<R: rand::Rng + rand::CryptoRng>(
        &self,
        plaintext: T,
        mut output: Lwe<&mut [T]>,
        parameters: &LweClientParameters<'_, T, M>,
        rng: &mut R,
    ) {
        LwePublicKey::encrypt_encoded_to(
            self,
            plaintext,
            &mut output,
            parameters.codec().ciphertext_modulus(),
            parameters.noise(),
            rng,
        );
    }
}

fn check_dimension(expected: usize, actual: usize) -> Result<(), ClientError> {
    if actual != expected {
        return Err(ClientError::KeyDimensionMismatch { expected, actual });
    }
    Ok(())
}
