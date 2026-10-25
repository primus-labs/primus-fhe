use primus_integer::{BigUint, multiply_many_values};

fn compose_u32(limbs: &[u32]) -> u128 {
    assert!(limbs.len() <= 4);
    limbs
        .iter()
        .rev()
        .fold(0u128, |value, &limb| (value << u32::BITS) | limb as u128)
}

fn compose_u64(limbs: &[u64]) -> u128 {
    assert!(limbs.len() <= 2);
    limbs
        .iter()
        .rev()
        .fold(0u128, |value, &limb| (value << u64::BITS) | limb as u128)
}

fn split_u128(value: u128) -> Vec<u64> {
    vec![value as u64, (value >> u64::BITS) as u64]
}

/// Check limb order and representation-sensitive equality; a u128 product supplies the oracle.
#[test]
fn representation_and_product_contracts() {
    let factors = [134_215_681u32, 134_176_769, 132_120_577];
    let product = multiply_many_values(&factors);
    let expected = factors.into_iter().map(u128::from).product::<u128>();

    assert_eq!(compose_u32(product.digits()), expected);
    assert_eq!(product.bit_width(), expected.bit_width());
    assert_eq!(product.checked_bit_width(), Some(expected.bit_width()));
    assert!(!product.is_zero());

    assert_eq!(BigUint(&[1u32, 2][..]), BigUint(vec![1u32, 2]));

    let padded = BigUint(&[1u32, 0][..]);
    assert_ne!(BigUint(&[1u32][..]), padded);
    assert_eq!(padded.bit_width(), 1);
    assert_eq!(padded.checked_bit_width(), Some(1));

    let zero = BigUint(&[0u32; 2][..]);
    assert!(zero.is_zero());
    assert_eq!(zero.bit_width(), 0);
    assert_eq!(zero.checked_bit_width(), Some(0));

    let empty = BigUint(&[] as &[u64]);
    assert_eq!(empty.bit_width(), 0);
    assert_eq!(empty.checked_bit_width(), Some(0));
    // Ignore a padded high limb, while counting a significant bit beyond bit 64.
    let wide = BigUint(&[0u64, 1u64 << 62, 0][..]);
    let expected_width = (1u128 << 126).bit_width();
    assert_eq!(wide.bit_width(), expected_width);
    assert_eq!(wide.checked_bit_width(), Some(expected_width));

    assert!(std::panic::catch_unwind(|| multiply_many_values::<u32>(&[])).is_err());
}

/// All-ones limbs force carry/borrow chains, including overflow beyond the final limb.
#[test]
fn scalar_operations_propagate_across_limbs() {
    for (input, expected, expected_carry) in [
        ([u32::MAX, u32::MAX, 7, 9], [0, 0, 8, 9], false),
        ([u32::MAX; 4], [0; 4], true),
    ] {
        let mut output = [0u32; 4];
        let carry = BigUint(&input[..]).add_value_to(1, &mut BigUint(&mut output[..]));
        assert_eq!((output, carry), (expected, expected_carry));
    }

    for (input, expected, expected_borrow) in [
        ([0u32, 0, 7, 9], [u32::MAX, u32::MAX, 6, 9], false),
        ([0u32; 4], [u32::MAX; 4], true),
    ] {
        let mut output = [0u32; 4];
        let borrow = BigUint(&input[..]).sub_value_to(1, &mut BigUint(&mut output[..]));
        assert_eq!((output, borrow), (expected, expected_borrow));
    }

    let original = [u32::MAX, 5, 7];
    let mut assigned = BigUint(original.to_vec());
    assert!(!assigned.add_value_assign(2));
    assert_eq!(compose_u32(assigned.digits()), compose_u32(&original) + 2);
    assert!(!assigned.sub_value_assign(2));
    assert_eq!(assigned.digits(), original);

    let limbs = [0xfedc_ba98u32, 0x7654_3210, 0x1234_5678];
    let scalar = 0x0123_4567u32;
    let input = BigUint(&limbs[..]);
    let expected_product = compose_u32(&limbs) * scalar as u128;

    let mut output = [0u32; 3];
    let carry = input.mul_value_to(scalar, &mut BigUint(&mut output[..]));
    assert_eq!(
        compose_u32(&[output[0], output[1], output[2], carry]),
        expected_product
    );

    let mut assigned = BigUint(limbs.to_vec());
    let carry = assigned.mul_value_assign(scalar);
    assert_eq!(assigned.digits(), output);
    assert_eq!(
        carry as u128,
        expected_product >> (u32::BITS * limbs.len() as u32)
    );

    let initial_acc = [11u32, 13, 17];
    let mut acc = initial_acc;
    let carry = input.mul_value_add_to(scalar, &mut BigUint(&mut acc[..]));
    assert_eq!(
        compose_u32(&[acc[0], acc[1], acc[2], carry]),
        expected_product + compose_u32(&initial_acc),
    );
}

/// A dense u128 value checks cross-limb shifts and slice arithmetic independently.
#[test]
fn fixed_width_shifts_addition_and_subtraction_match_u128() {
    let raw = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128;
    let mut shifted = BigUint(split_u128(raw));
    let carry = shifted.left_shift_assign(7);
    assert_eq!(compose_u64(shifted.digits()), raw << 7);
    assert_eq!(carry, (raw >> (u128::BITS - 7)) as u64);

    shifted = BigUint(split_u128(raw));
    shifted.right_shift_assign(11);
    assert_eq!(compose_u64(shifted.digits()), raw >> 11);

    let lhs_limbs = [u32::MAX, 5, 7];
    let rhs_limbs = [2u32, 4, 1];
    let lhs = BigUint(&lhs_limbs[..]);
    let rhs = BigUint(&rhs_limbs[..]);
    let lhs_raw = compose_u32(&lhs_limbs);
    let rhs_raw = compose_u32(&rhs_limbs);

    let mut output = [0u32; 3];
    assert!(!lhs.add_to(&rhs, &mut BigUint(&mut output[..])));
    assert_eq!(compose_u32(&output), lhs_raw + rhs_raw);

    let mut assigned = BigUint(lhs_limbs.to_vec());
    assert!(!assigned.add_assign(&rhs));
    assert_eq!(compose_u32(assigned.digits()), lhs_raw + rhs_raw);

    assert!(!lhs.sub_to(&rhs, &mut BigUint(&mut output[..])));
    assert_eq!(compose_u32(&output), lhs_raw - rhs_raw);

    assert!(!assigned.sub_assign(&rhs));
    assert_eq!(assigned.digits(), lhs_limbs);
}

/// Compute a canonical sum without overflowing u128; both inputs are below modulus.
fn add_modulo(lhs: u128, rhs: u128, modulus: u128) -> u128 {
    if lhs >= modulus - rhs {
        lhs - (modulus - rhs)
    } else {
        lhs + rhs
    }
}

/// Use a modulus above 2^127 so addition must account for the discarded top carry.
#[test]
fn modular_operations_handle_fixed_width_overflow() {
    let modulus_raw = 0xc0ff_ee15_dead_beef_face_b00c_1337_4242u128;
    let lhs_raw = modulus_raw - 100;
    let rhs_raw = modulus_raw - 200;
    let modulus = BigUint(split_u128(modulus_raw));
    let lhs = BigUint(split_u128(lhs_raw));
    let rhs = BigUint(split_u128(rhs_raw));
    let expected_add = add_modulo(lhs_raw, rhs_raw, modulus_raw);

    let mut output = BigUint(vec![0u64; 2]);
    lhs.add_modulo_to(&rhs, &mut output, &modulus);
    assert_eq!(compose_u64(output.digits()), expected_add);

    let mut assigned = lhs.clone();
    assigned.add_modulo_assign(&rhs, &modulus);
    assert_eq!(compose_u64(assigned.digits()), expected_add);

    rhs.sub_modulo_to(&lhs, &mut output, &modulus);
    assert_eq!(compose_u64(output.digits()), modulus_raw - 100);

    let mut assigned = rhs.clone();
    assigned.sub_modulo_assign(&lhs, &modulus);
    assert_eq!(compose_u64(assigned.digits()), modulus_raw - 100);

    let mut reversed = lhs.clone();
    reversed.sub_modulo_rev_assign(&rhs, &modulus);
    assert_eq!(compose_u64(reversed.digits()), modulus_raw - 100);

    lhs.neg_modulo_to(&mut output, &modulus);
    assert_eq!(compose_u64(output.digits()), 100);

    let mut negated = lhs;
    negated.neg_modulo_assign(&modulus);
    assert_eq!(compose_u64(negated.digits()), 100);
}
