use algebra::{
    integer::{AsInto, UnsignedInteger},
    reduce::ModulusValue,
};

/// Encodes a message.
///
/// # Parameters
///
/// - `t` is message space
/// - `q` is LWE modulus value.
#[inline]
pub fn encode<M, C>(message: M, t: C, q: ModulusValue<C>) -> C
where
    C: UnsignedInteger,
    M: TryInto<C>,
{
    match q {
        ModulusValue::Native => encode_native(message, t),
        ModulusValue::PowerOf2(q) => encode_pow_of_2(message, t, q),
        ModulusValue::Prime(q) | ModulusValue::Others(q) => encode_normal(message, t, q),
    }
}

/// Encodes a message.
///
/// # Parameters
///
/// - `t` is message space
/// - `q` is LWE modulus value.
/// - This function needs `q` and `t` are power of 2.
///
/// # Panic
///
/// Panics if the message exceeds the message space.
#[inline]
pub fn encode_pow_of_2<M, C>(message: M, t: C, q: C) -> C
where
    C: UnsignedInteger,
    M: TryInto<C>,
{
    debug_assert!(q.is_power_of_two() && t.is_power_of_two());
    // Shift the message to the most significant part of `C`.
    let message: C = message
        .try_into()
        .map_err(|_| "out of range integral type conversion attempted")
        .unwrap();
    assert!(
        message < t,
        "message {message} is bigger than the message space"
    );
    message << (q / t).trailing_zeros()
}

/// Encodes a message.
///
/// # Parameters
///
/// - `t` is message space
/// - This function needs `t` be power of 2.
///
/// # Panic
///
/// Panics if the message exceeds the message space.
#[inline]
pub fn encode_native<M, C>(message: M, t: C) -> C
where
    C: UnsignedInteger,
    M: TryInto<C>,
{
    debug_assert!(t.is_power_of_two());
    let message: C = message
        .try_into()
        .map_err(|_| "out of range integral type conversion attempted")
        .unwrap();
    assert!(
        message < t,
        "message {message} is bigger than the message space"
    );
    message << (C::BITS - t.trailing_zeros())
}

pub fn encode_normal<M, C>(message: M, t: C, q: C) -> C
where
    C: UnsignedInteger,
    M: TryInto<C>,
{
    let message: C = message
        .try_into()
        .map_err(|_| "out of range integral type conversion attempted")
        .unwrap();

    let q: f64 = q.as_into();
    let t: f64 = t.as_into();
    let m: f64 = message.as_into();

    (q / t * m).round().as_into()
}

/// Decodes an encode value.
///
/// # Parameters
///
/// - `t` is message space
/// - `q` is LWE modulus value.
#[inline]
pub fn decode<M, C>(cipher: C, t: C, q: ModulusValue<C>) -> M
where
    M: TryFrom<C>,
    C: UnsignedInteger,
{
    match q {
        ModulusValue::Native => decode_native(cipher, t),
        ModulusValue::PowerOf2(q) => decode_pow_of_2(cipher, t, q),
        ModulusValue::Prime(q) | ModulusValue::Others(q) => decode_normal(cipher, t, q),
    }
}

pub fn decode_normal<M, C>(cipher: C, t: C, q: C) -> M
where
    M: TryFrom<C>,
    C: UnsignedInteger,
{
    debug_assert!(t.is_power_of_two());
    let q_f: f64 = q.as_into();
    let t_f: f64 = t.as_into();
    let c: f64 = cipher.as_into();
    let temp: C = (c / (q_f / t_f)).round().as_into();
    let temp = if temp >= t { temp - t } else { temp };

    M::try_from(temp)
        .map_err(|_| "out of range integral type conversion attempted")
        .unwrap()
}

/// Decodes an encode value.
///
/// # Parameters
///
/// - `t` is message space
/// - `q` is LWE modulus value.
/// - This function needs `q` and `t` are power of 2.
///
/// # Panic
///
/// Panics if the decoded message cannot fit in `M`.
#[inline]
pub fn decode_pow_of_2<M, C>(cipher: C, t: C, q: C) -> M
where
    M: TryFrom<C>,
    C: UnsignedInteger,
{
    debug_assert!(q.is_power_of_two() && t.is_power_of_two());
    // Move the message to the least significant part of `C`.
    // Leave one more bit for round.
    let temp = cipher >> ((q / t).trailing_zeros() - 1);
    let decoded = ((temp + C::ONE) >> 1u32) & (t - C::ONE);

    M::try_from(decoded)
        .map_err(|_| "out of range integral type conversion attempted")
        .unwrap()
}

/// Decodes an encode value.
///
/// # Parameters
///
/// - `t` is message space
/// - `q` is LWE modulus value.
/// - This function needs `t` be power of 2.
///
/// # Panic
///
/// Panics if the decoded message cannot fit in `M`.
#[inline]
pub fn decode_native<M, C>(cipher: C, t: C) -> M
where
    M: TryFrom<C>,
    C: UnsignedInteger,
{
    debug_assert!(t.is_power_of_two());
    // Move the message to the least significant part of `C`.
    // Leave one more bit for round.
    let temp = cipher >> (C::BITS - t.trailing_zeros() - 1);
    let decoded = ((temp + C::ONE) >> 1u32) & (t - C::ONE);

    M::try_from(decoded)
        .map_err(|_| "out of range integral type conversion attempted")
        .unwrap()
}
