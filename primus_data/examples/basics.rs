//! Example: polymorphic data processing with `primus_data`.
//!
//! This example demonstrates how to write generic functions that operate on
//! any contiguous buffer type — slices, arrays, Vec, Box<[T]>, Arc<[T]>
//! — using the [`Data`], [`DataMut`], and [`DataOwned`] traits.

use std::sync::Arc;

use primus_data::{Data, DataMut, DataOwned};

fn main() {
    // -----------------------------------------------------------------------
    // 1. Read-only generic computation over different backends
    // -----------------------------------------------------------------------
    println!("=== Read-only: mean ===");

    fn mean<D: Data<Elem = f64>>(buf: &D) -> f64 {
        let sum: f64 = buf.iter().sum();
        sum / buf.len() as f64
    }

    let vec_data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
    let box_data: Box<[f64]> = vec![1.0, 2.0, 3.0, 4.0, 5.0].into_boxed_slice();
    let arr_data = [1.0, 2.0, 3.0, 4.0, 5.0];
    let arc_data: Arc<[f64]> = Arc::from([1.0, 2.0, 3.0, 4.0, 5.0]);

    println!("  Vec:       mean = {:.2}", mean(&vec_data));
    println!("  Box<[T]>:  mean = {:.2}", mean(&box_data));
    println!("  [T; N]:    mean = {:.2}", mean(&arr_data));
    println!("  Arc<[T]>:  mean = {:.2}", mean(&arc_data));

    // Borrowed views work too — the same function accepts &[f64] and &[f64; N].
    let r: &[f64] = &vec_data;
    let ra: &[f64; 5] = &arr_data;
    println!("  &[T]:      mean = {:.2}", mean(&r));
    println!("  &[T; N]:   mean = {:.2}", mean(&ra));

    // -----------------------------------------------------------------------
    // 2. In-place mutation via DataMut
    // -----------------------------------------------------------------------
    println!();
    println!("=== In-place: normalize to [0, 1] ===");

    fn normalize<D: DataMut<Elem = f64>>(buf: &mut D) {
        let min = *buf.iter().min_by(|a, b| a.partial_cmp(b).unwrap()).unwrap();
        let max = *buf.iter().max_by(|a, b| a.partial_cmp(b).unwrap()).unwrap();
        let range = max - min;
        if range > 0.0 {
            for x in buf.iter_mut() {
                *x = (*x - min) / range;
            }
        }
    }

    let mut v = vec![10.0, 20.0, 30.0, 40.0, 50.0];
    normalize(&mut v);
    println!("  Vec:       {:?}", v.as_slice());

    let mut b: Box<[f64]> = vec![0.0, 25.0, 50.0, 75.0, 100.0].into_boxed_slice();
    normalize(&mut b);
    println!("  Box<[T]>:  {:?}", b.as_slice());

    let mut a = [5.0, 10.0, 15.0, 20.0, 25.0];
    normalize(&mut a);
    println!("  [T; N]:    {:?}", a.as_slice());

    // &mut [T] also works.
    let mut raw = vec![100.0, 200.0, 300.0];
    let mut ms: &mut [f64] = &mut raw;
    normalize(&mut ms);
    println!("  &mut [T]:  {:?}", &raw[..]);

    // -----------------------------------------------------------------------
    // 3. DataOwned: construction and consumption
    // -----------------------------------------------------------------------
    println!();
    println!("=== DataOwned: from_slice / into_iter ===");

    // Build an owned buffer from a slice.
    let from_slice = Vec::<i32>::from_slice(&[10, 20, 30]);
    println!("  Vec::from_slice:  {:?}", from_slice.as_slice());

    let from_slice_box = Box::<[i32]>::from_slice(&[40, 50, 60]);
    println!("  Box::from_slice:   {:?}", from_slice_box.as_slice());

    // Consume an owned buffer back into an iterator.
    let doubled: Vec<i32> = DataOwned::into_iter(from_slice).map(|x| x * 2).collect();
    println!("  Vec after map:     {:?}", doubled);

    let tripled: Vec<i32> = DataOwned::into_iter(from_slice_box)
        .map(|x| x * 3)
        .collect();
    println!("  Box after map:     {:?}", tripled);

    // -----------------------------------------------------------------------
    // 4. Pipeline: read from one form, process, collect into another
    // -----------------------------------------------------------------------
    println!();
    println!("=== Pipeline: filter → Box<[T]> ===");

    fn keep_even<D: Data<Elem = i32>>(buf: &D) -> Box<[i32]> {
        buf.iter().copied().filter(|x| x % 2 == 0).collect()
    }

    let source = [1, 2, 3, 4, 5, 6, 7, 8];
    let result = keep_even(&source);
    println!("  Input:  {:?}", source);
    println!("  Output: {:?}", result.as_slice());
}
