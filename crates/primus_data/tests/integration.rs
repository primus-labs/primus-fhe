//! Check storage bindings and owned constructors, not the containers themselves.

use std::sync::Arc;

use primus_data::{Data, DataMut, DataOwned};

const VALUES: [u64; 4] = [1, 2, 3, 4];

fn assert_read<D: Data<Elem = u64>>(data: D) {
    assert_eq!(data.as_slice(), VALUES);
    assert_eq!(data.len(), VALUES.len());
}

fn write<D: DataMut<Elem = u64>>(mut data: D) {
    data.as_mut_slice().fill(9);
}

/// Owned constructors preserve elements; owned and borrowed views expose the same storage.
#[test]
fn standard_backends() {
    let source = VALUES.to_vec();
    let allocation = source.as_ptr();
    let mut vec = Vec::<u64>::from_vec(source);
    assert_eq!(vec.as_ptr(), allocation);
    let mut boxed = Box::<[u64]>::from_slice(&VALUES);
    let arc: Arc<[u64]> = Arc::from(VALUES);

    assert_read(&vec);
    assert_read(&boxed);
    assert_read(&arc);
    assert_read(VALUES);
    assert_read(VALUES.as_slice());

    write(&mut vec);
    write(&mut boxed);
    assert_eq!(vec, [9; 4]);
    assert_eq!(*boxed, [9; 4]);

    let mut array = VALUES;
    write(&mut array);
    assert_eq!(array, [9; 4]);

    let mut slice_storage = VALUES;
    write(&mut slice_storage[..]);
    assert_eq!(slice_storage, [9; 4]);
}

/// Aligned owners participate in the same Data/DataMut contracts as ordinary storage.
#[cfg(feature = "aligned-vec")]
#[test]
fn aligned_backends() {
    use aligned_vec::{AVec, RuntimeAlign};

    let mut vec = AVec::<u64, RuntimeAlign>::from_slice(64, &VALUES);
    assert_read(&vec);
    write(&mut vec);
    assert_eq!(vec.as_slice(), &[9; 4]);

    let mut boxed = AVec::<u64, RuntimeAlign>::from_slice(64, &VALUES).into_boxed_slice();
    assert_read(&boxed);
    write(&mut boxed);
    assert_eq!(&*boxed, &[9; 4]);
}
