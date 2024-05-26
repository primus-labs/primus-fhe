/// LWE bool Plain text
pub type LWEBoolMessage = bool;

/// LWE modulus type
pub type LWEModulusType = u16;

/// Encodes a message
#[inline]
pub fn encode(message: LWEBoolMessage, lwe_modulus: LWEModulusType) -> LWEModulusType {
    if message {
        lwe_modulus >> 2
    } else {
        0
    }
}

/// Decodes a plain text
pub fn decode(plaintext: LWEModulusType, lwe_modulus: LWEModulusType) -> LWEBoolMessage {
    assert!(lwe_modulus.is_power_of_two() && lwe_modulus >= 8);

    let temp = plaintext >> (lwe_modulus.trailing_zeros() - 3);
    let decoded = ((temp >> 1) + (temp & 1)) & 3;

    match decoded {
        0 => false,
        1 => true,
        _ => panic!("Wrong decoding output: {:?}", decoded),
    }
}
