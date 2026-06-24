use std::sync::Arc;

use primus_data::{Data, DataMut, DataOwned};

// ---------------------------------------------------------------------------
// Generic exercise functions.
//
// These are the core of the test suite: because they are generic over `D`,
// the compiler **must** dispatch through the trait methods rather than
// inherent methods on `Vec`, `Box<[T]>`, or `[T]`.
// ---------------------------------------------------------------------------

/// Verifies every `Data` method on a 5-element buffer.
fn exercise_data<D: Data<Elem = u64>>(buf: &D) {
    assert_eq!(buf.len(), 5);
    assert!(!buf.is_empty());
    assert_eq!(buf.first(), Some(&1));
    assert_eq!(buf.last(), Some(&5));

    let sum: u64 = buf.iter().sum();
    assert_eq!(sum, 15);

    let (left, right) = buf.split_at(2);
    assert_eq!(left, &[1, 2]);
    assert_eq!(right, &[3, 4, 5]);

    let (left, right) = buf.split_at(0);
    assert!(left.is_empty());
    assert_eq!(right.len(), 5);

    unsafe {
        let (left, right) = buf.split_at_unchecked(2);
        assert_eq!(left.len(), 2);
        assert_eq!(right.len(), 3);
    }

    let (chunks, remainder) = buf.as_chunks::<2>();
    assert_eq!(chunks, &[[1, 2], [3, 4]]);
    assert_eq!(remainder, &[5]);

    let (chunks, remainder) = buf.as_chunks::<5>();
    assert_eq!(chunks.len(), 1);
    assert!(remainder.is_empty());

    let (chunks, remainder) = buf.as_chunks::<6>();
    assert!(chunks.is_empty());
    assert_eq!(remainder.len(), 5);

    let mut iter = buf.chunks_exact(2);
    assert_eq!(iter.next(), Some(&[1, 2][..]));
    assert_eq!(iter.next(), Some(&[3, 4][..]));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.remainder(), &[5]);
}

/// Verifies every `DataMut` method on a 5-element buffer.
fn exercise_data_mut<D: DataMut<Elem = u64>>(buf: &mut D) {
    assert_eq!(buf.first_mut(), Some(&mut 1));
    assert_eq!(buf.last_mut(), Some(&mut 5));

    *buf.first_mut().unwrap() = 10;
    *buf.last_mut().unwrap() = 50;
    assert_eq!(buf.as_slice(), &[10, 2, 3, 4, 50]);

    buf.reverse();
    assert_eq!(buf.as_slice(), &[50, 4, 3, 2, 10]);

    buf.fill(7);
    assert_eq!(buf.as_slice(), &[7; 5]);

    buf.copy_from_slice(&[1, 2, 3, 4, 5]);

    let (left, right) = buf.split_at_mut(2);
    left.fill(8);
    right.fill(9);
    assert_eq!(buf.as_slice(), &[8, 8, 9, 9, 9]);

    unsafe {
        let (left, right) = buf.split_at_mut_unchecked(3);
        left.copy_from_slice(&[1, 2, 3]);
        right.copy_from_slice(&[4, 5]);
    }
    assert_eq!(buf.as_slice(), &[1, 2, 3, 4, 5]);

    for (i, chunk) in buf.chunks_exact_mut(2).enumerate() {
        match i {
            0 => chunk.copy_from_slice(&[10, 20]),
            1 => chunk.copy_from_slice(&[30, 40]),
            _ => unreachable!(),
        }
    }
    assert_eq!(buf.as_slice(), &[10, 20, 30, 40, 5]);

    let (chunks, remainder) = buf.as_chunks_mut::<2>();
    chunks[0] = [100, 200];
    chunks[1] = [300, 400];
    remainder[0] = 500;
    assert_eq!(buf.as_slice(), &[100, 200, 300, 400, 500]);
}

/// Verifies `DataOwned` construction and consumption.
fn exercise_data_owned<D: DataOwned<Elem = u64>>(buf: D) {
    assert_eq!(buf.as_slice(), &[1, 2, 3]);
    let items: Vec<u64> = buf.into_iter().collect();
    assert_eq!(items, &[1, 2, 3]);
}

/// Polymorphic read-only compute (proves `Data` dispatch).
fn sum<D: Data<Elem = u64>>(buf: &D) -> u64 {
    buf.iter().sum()
}

/// Polymorphic mutate (proves `DataMut` dispatch).
fn double<D: DataMut<Elem = u64>>(buf: &mut D) {
    for x in buf.iter_mut() {
        *x *= 2;
    }
}

// ---------------------------------------------------------------------------
// Backend smoke tests — one per backend, each calling the generic exercises.
// These prove that every backend's impl compiles and behaves identically.
// ---------------------------------------------------------------------------

#[test]
fn backend_vec() {
    exercise_data(&vec![1u64, 2, 3, 4, 5]);
    exercise_data_mut(&mut vec![1u64, 2, 3, 4, 5]);
    exercise_data_owned(vec![1u64, 2, 3]);

    let mut v = vec![1u64, 2, 3];
    double(&mut v);
    assert_eq!(sum(&v), 12);
}

#[test]
fn backend_box_slice() {
    let b: Box<[u64]> = vec![1, 2, 3, 4, 5].into_boxed_slice();
    exercise_data(&b);

    let mut b: Box<[u64]> = vec![1, 2, 3, 4, 5].into_boxed_slice();
    exercise_data_mut(&mut b);

    exercise_data_owned::<Box<[u64]>>(vec![1, 2, 3].into_boxed_slice());
}

#[test]
fn backend_array() {
    exercise_data(&[1u64, 2, 3, 4, 5]);
    exercise_data_mut(&mut [1u64, 2, 3, 4, 5]);
}

#[test]
fn backend_arc_slice() {
    let arc: Arc<[u64]> = Arc::from([1u64, 2, 3, 4, 5]);
    exercise_data(&arc);
    assert_eq!(sum(&arc), 15);
}

#[test]
fn backend_ref_slice() {
    let owner = vec![1u64, 2, 3, 4, 5];
    let r: &[u64] = &owner;
    exercise_data(&r);
    assert_eq!(sum(&r), 15);
}

#[test]
fn backend_mut_slice() {
    let mut owner = vec![1u64, 2, 3, 4, 5];
    {
        let mut r: &mut [u64] = &mut owner;
        exercise_data(&r);
        exercise_data_mut(&mut r);
    }
    // Verify mutations flowed through to the backing store.
    assert_eq!(owner, &[100, 200, 300, 400, 500]);
}

#[test]
fn backend_ref_array() {
    let owner = [1u64, 2, 3, 4, 5];
    let r: &[u64; 5] = &owner;
    exercise_data(&r);
    assert_eq!(sum(&r), 15);
}

#[test]
fn backend_mut_array() {
    let mut owner = [1u64, 2, 3, 4, 5];
    {
        let mut r: &mut [u64; 5] = &mut owner;
        exercise_data(&r);
        exercise_data_mut(&mut r);
    }
    assert_eq!(owner, [100, 200, 300, 400, 500]);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[allow(clippy::const_is_empty)]
#[test]
fn empty_buffers() {
    let v: Vec<u64> = vec![];
    assert!(v.is_empty());
    assert_eq!(v.len(), 0);
    assert_eq!(v.first(), None);
    assert_eq!(v.last(), None);
    assert_eq!(sum(&v), 0);

    let a: [u64; 0] = [];
    assert!(a.is_empty());
    assert_eq!(a.len(), 0);

    let r: &[u64] = &[];
    assert!(r.is_empty());

    let mut mv: Vec<u64> = vec![];
    assert_eq!(mv.first_mut(), None);
    assert_eq!(mv.last_mut(), None);
    mv.fill(1); // fill on empty is a no-op
    assert!(mv.is_empty());
}

#[test]
fn single_element() {
    let v = vec![42u64];
    assert_eq!(v.len(), 1);
    assert_eq!(v.first(), Some(&42));
    assert_eq!(v.last(), Some(&42));

    let (left, right) = v.split_at(1);
    assert_eq!(left, &[42]);
    assert_eq!(right, &[]);
}

#[test]
fn single_element_mut() {
    let mut v = vec![7u64];
    *v.first_mut().unwrap() = 99;
    assert_eq!(v.as_slice(), &[99]);
    v.reverse(); // reversing 1 element is a no-op
    assert_eq!(v.as_slice(), &[99]);
}

#[test]
fn data_owned_constructors() {
    assert_eq!(Vec::<u64>::from_slice(&[1, 2, 3]).as_slice(), &[1, 2, 3]);
    assert_eq!(Vec::from_vec(vec![1, 2, 3]).as_slice(), &[1, 2, 3]);
    assert_eq!(Box::<[u64]>::from_slice(&[4, 5, 6]).as_slice(), &[4, 5, 6]);
    assert_eq!(Box::<[u64]>::from_vec(vec![7, 8, 9]).as_slice(), &[7, 8, 9]);

    // from_slice on empty
    assert!(Vec::<u64>::from_slice(&[]).is_empty());
    assert!(Box::<[u64]>::from_slice(&[]).is_empty());
}
