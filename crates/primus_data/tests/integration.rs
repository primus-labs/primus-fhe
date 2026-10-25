//! Check storage bindings and owned constructors, not the containers themselves.

use std::sync::Arc;

use primus_data::{Data, DataMut, DataOwned};

const VALUES: [u64; 4] = [1, 2, 3, 4];

fn assert_read<D: Data<Elem = u64>>(data: &D) {
    assert_eq!(data.as_slice(), VALUES);
    assert_eq!(data.len(), VALUES.len());
    assert!(!data.is_empty());
}

fn assert_write<D: DataMut<Elem = u64>>(data: &mut D) {
    data.as_mut_slice().fill(9);
    assert_eq!(data.as_slice(), &[9; 4]);
}

/// Owned constructors preserve elements; owned and borrowed views expose the same storage.
#[test]
fn standard_backends() {
    let mut vec = Vec::<u64>::from_slice(&VALUES);
    let mut boxed = Box::<[u64]>::from_vec(VALUES.to_vec());
    let arc: Arc<[u64]> = Arc::from(VALUES);
    let slice: &[u64] = &VALUES;
    let array_ref: &[u64; 4] = &VALUES;

    assert_read(&vec);
    assert_read(&&vec);
    assert_read(&boxed);
    assert_read(&&boxed);
    assert_read(&arc);
    assert_read(&&arc);
    assert_read(&VALUES);
    assert_read(&slice);
    assert_read(&array_ref);

    assert_write(&mut &mut vec);
    assert_write(&mut &mut boxed);

    let mut array = VALUES;
    assert_write(&mut array);

    let mut slice_storage = VALUES;
    let mut slice: &mut [u64] = &mut slice_storage;
    assert_write(&mut slice);

    let mut array_storage = VALUES;
    let mut array_ref: &mut [u64; 4] = &mut array_storage;
    assert_write(&mut array_ref);
}

/// Aligned owners participate in the same Data/DataMut contracts as ordinary storage.
#[cfg(feature = "aligned-vec")]
#[test]
fn aligned_backends() {
    use aligned_vec::{AVec, RuntimeAlign};

    let mut vec = AVec::<u64, RuntimeAlign>::from_slice(64, &VALUES);
    assert_read(&vec);
    assert_read(&&vec);
    assert_write(&mut &mut vec);

    let mut boxed = AVec::<u64, RuntimeAlign>::from_slice(64, &VALUES).into_boxed_slice();
    assert_read(&boxed);
    assert_read(&&boxed);
    assert_write(&mut &mut boxed);
}
