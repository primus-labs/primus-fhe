//! Optional serde support preserves the complete fixed-width representation.

use primus_integer::BigUint;

#[test]
fn borrowed_and_owned_storage_preserve_all_limbs() {
    // The final zero is part of the representation, not removable padding.
    let limbs = [u64::MAX, 1, 0];
    let borrowed = BigUint(limbs.as_slice());
    let owned = BigUint(limbs.to_vec());
    let encoded = serde_json::to_string(&borrowed).unwrap();
    assert_eq!(encoded, serde_json::to_string(&owned).unwrap());

    let decoded: BigUint<Vec<u64>> = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, owned);
    let decoded: BigUint<[u64; 3]> = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.0, limbs);
}
