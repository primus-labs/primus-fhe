//! Optional serde support preserves raw mask/body storage without parameter metadata.

use primus_lattice::lwe::{Lwe, MultiMsgLwe};

#[test]
fn borrowed_and_owned_ciphertexts_preserve_mask_body_order() {
    let lwe = Lwe::new(vec![1u32, u32::MAX, 3]);
    let encoded = serde_json::to_string(&lwe.as_view()).unwrap();
    assert_eq!(encoded, serde_json::to_string(&lwe).unwrap());
    let decoded: Lwe<Vec<u32>> = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.a_b(), (&[1, u32::MAX][..], 3));

    // The split between the shared mask and bodies remains caller-supplied.
    let packed = MultiMsgLwe::new(vec![1u64, u64::MAX, 3, 4]);
    let encoded = serde_json::to_string(&packed.as_view()).unwrap();
    assert_eq!(encoded, serde_json::to_string(&packed).unwrap());
    let decoded: MultiMsgLwe<Box<[u64]>> = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.a_b(2), (&[1, u64::MAX][..], &[3, 4][..]));
}
