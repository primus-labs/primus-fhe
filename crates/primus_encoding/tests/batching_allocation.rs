#![cfg(feature = "batching")]

use primus_encoding::BatchingEncoder;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

thread_local! {
    static COUNT: Cell<Option<usize>> = const { Cell::new(None) };
}

struct Allocator;

fn record(pointer: *mut u8) {
    if !pointer.is_null() {
        let _ = COUNT.try_with(|count| {
            if let Some(value) = count.get() {
                count.set(Some(value + 1));
            }
        });
    }
}

// SAFETY: All original allocation arguments are forwarded unchanged to System.
// Counting uses nonallocating thread-local Cells and never inspects memory.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplied this GlobalAlloc layout.
        let pointer = unsafe { System.alloc(layout) };
        record(pointer);
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplied this GlobalAlloc layout.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        record(pointer);
        pointer
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: The original allocation contract is forwarded unchanged.
        let pointer = unsafe { System.realloc(pointer, layout, size) };
        record(pointer);
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The allocation is returned with its original layout.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

#[test]
fn prepared_slot_conversions_automorphism_and_embedding_allocate_nothing() {
    let encoder = BatchingEncoder::try_new(PolyLength::new(32), BarrettModulus::new(257)).unwrap();
    let input = [3; 32];
    let mut coefficients = [19; 32];
    let mut scratch = [23; 32];
    let mut decoded = [0; 32];
    let mut rotated = [0; 32];
    let mut embedded = [29; 128];
    let mut extracted = [0; 32];
    COUNT.with(|count| count.set(Some(0)));
    encoder.encode_to(&input[..17], &mut coefficients);
    encoder.decode_to(&coefficients, &mut decoded, &mut scratch);
    encoder.automorphism_slots_to(&decoded, encoder.rotation_exponent(-1), &mut rotated);
    encoder.embed_to(&coefficients, &mut embedded);
    encoder.extract_to(&embedded, &mut extracted);
    let allocations = COUNT.with(|count| count.replace(None).unwrap());
    assert_eq!(allocations, 0);
    assert_eq!(extracted, coefficients);
}
