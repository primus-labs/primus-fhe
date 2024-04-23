/// Plain text type of the first layer LWE scheme
pub type LWEPlaintext = bool;

/// LWE ciphertext inner value type
pub type LWEContainer = u16;

/// Encodes a message
#[inline]
pub fn encode(message: LWEPlaintext, lwe_modulus: LWEContainer) -> LWEContainer {
    if message {
        lwe_modulus >> 2
    } else {
        0
    }
}

/// Decodes a encoded message
pub fn decode(encoded_message: LWEContainer, lwe_modulus: LWEContainer) -> bool {
    assert!(lwe_modulus.is_power_of_two() && lwe_modulus >= 8);

    let temp = encoded_message >> (lwe_modulus.trailing_zeros() - 3);
    let decoded = ((temp >> 1) + (temp & 1)) & 3;

    match decoded {
        0 => false,
        1 => true,
        _ => panic!("Wrong decoding output: {:?}", decoded),
    }
}
