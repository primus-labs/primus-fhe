use std::sync::Arc;

use primus_integer::Size;

/// Size counts payload bytes consistently for owners, arrays, and borrowed views.
#[test]
fn size_counts_each_supported_storage_backend() {
    let mut values = [1u32, 2, 3, 4];
    let slice: &[u32] = &values;
    let boxed: Box<[u32]> = values.into();
    let arc: Arc<[u32]> = Arc::from(values);

    assert_eq!(values.byte_count(), 16);
    assert_eq!(values.to_vec().byte_count(), 16);
    assert_eq!(slice.byte_count(), 16);
    assert_eq!(boxed.byte_count(), 16);
    assert_eq!(arc.byte_count(), 16);

    let mutable_slice: &mut [u32] = &mut values;
    assert_eq!(mutable_slice.byte_count(), 16);
}
