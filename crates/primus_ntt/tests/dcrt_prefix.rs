//! Prefix geometry and scheduling; individual transforms keep their math oracles.

use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64DcrtTable};
use primus_shape::PolyLength;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    hint::black_box,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    thread,
};

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    // The test harness can allocate concurrently on its own thread.
    static OBSERVED_THREAD: Cell<bool> = const { Cell::new(false) };
}
struct CountingAllocator;
fn note(pointer: *mut u8) {
    if !pointer.is_null()
        && COUNTING.load(SeqCst)
        && OBSERVED_THREAD.try_with(Cell::get).unwrap_or(false)
    {
        ALLOCATIONS.fetch_add(1, SeqCst);
    }
}
// SAFETY: Every operation delegates its original pointer/layout arguments to
// System. Atomic accounting also observes work on the already prepared pool.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        note(pointer);
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        note(pointer);
        pointer
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, layout, size) };
        note(result);
        result
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn allocation_count(operation: impl FnOnce()) -> usize {
    ALLOCATIONS.store(0, SeqCst);
    COUNTING.store(true, SeqCst);
    operation();
    COUNTING.store(false, SeqCst);
    ALLOCATIONS.load(SeqCst)
}

fn without_allocating(operation: impl FnOnce()) {
    assert_eq!(allocation_count(operation), 0, "prepared prefix transform");
}

fn allocate_once() {
    drop(black_box(Box::new(0_u64)));
}

fn check_allocation_scope() {
    let start = AtomicBool::new(false);
    let done = AtomicBool::new(false);
    thread::scope(|scope| {
        scope.spawn(|| {
            while !start.load(SeqCst) {
                thread::yield_now();
            }
            allocate_once();
            done.store(true, SeqCst);
        });
        // Start the unrelated thread before measuring. Both threads allocate
        // inside the window, so the count must include only this thread's call.
        let count = allocation_count(|| {
            allocate_once();
            start.store(true, SeqCst);
            while !done.load(SeqCst) {
                thread::yield_now();
            }
        });
        assert_eq!(count, 1, "only the registered test thread is counted");
    });
}

const N: usize = 4096;
const Q: [u64; 4] = [
    65537,
    1_073_692_673,
    1_125_899_906_826_241,
    1_152_921_504_606_830_593,
];

/// Check the forward output against the serial component oracle. The original
/// coefficients are the exact expected output of its inverse.
fn check_prefix(table: &U64DcrtTable, coefficients: &[u64], transformed: &[u64]) {
    let mut actual = coefficients.to_vec();
    let limbs = coefficients.len() / N;
    without_allocating(|| table.transform_prefix_slice(&mut actual));
    assert_eq!(actual, transformed, "prefix={limbs}");
    without_allocating(|| table.inverse_transform_prefix_slice(&mut actual));
    assert_eq!(actual, coefficients, "inverse prefix={limbs}");
}

#[test]
fn complete_prefix_transforms_match_serial_and_reject_geometry_before_writes() {
    OBSERVED_THREAD.set(true);
    check_allocation_scope();
    #[cfg(not(feature = "parallel"))]
    let table = U64DcrtTable::new(PolyLength::new(N), &Q.map(BarrettModulus::new)).unwrap();
    #[cfg(feature = "parallel")]
    let pools = [1, 2, 4].map(|workers| {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();
        // Register every worker after it starts, and keep the pools alive for
        // all measurements. The positive check exercises the counter on a
        // worker before any transform runs.
        pool.broadcast(|_| OBSERVED_THREAD.set(true));
        pool.install(|| {
            assert_eq!(
                allocation_count(allocate_once),
                1,
                "registered Rayon worker"
            )
        });
        pool
    });
    #[cfg(feature = "parallel")]
    let table = pools[0]
        .install(|| U64DcrtTable::new(PolyLength::new(N), &Q.map(BarrettModulus::new)).unwrap());
    // Compute the serial reference once per prefix and share it across pool sizes.
    for limbs in 1..=Q.len() {
        let coefficients = Q[..limbs]
            .iter()
            .flat_map(|&q| (0..N).map(move |i| if i % 7 == 0 { q - 1 } else { i as u64 }))
            .collect::<Vec<_>>();
        let mut transformed = coefficients.clone();
        let (transformed_limbs, _) = transformed.as_chunks_mut::<N>();
        for (limb, component) in transformed_limbs.iter_mut().zip(table.iter()) {
            component.transform_slice(limb);
        }
        #[cfg(feature = "parallel")]
        for pool in &pools {
            pool.install(|| check_prefix(&table, &coefficients, &transformed));
        }
        #[cfg(not(feature = "parallel"))]
        check_prefix(&table, &coefficients, &transformed);
    }

    for length in [0, N - 1, N + 1, table.rns_poly_len() + N] {
        for inverse in [false, true] {
            let mut values = vec![u64::MAX; length];
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    if inverse {
                        table.inverse_transform_prefix_slice(&mut values);
                    } else {
                        table.transform_prefix_slice(&mut values);
                    }
                }))
                .is_err()
            );
            assert!(values.iter().all(|&value| value == u64::MAX));
        }
    }
}
