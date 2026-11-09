#![cfg(any(feature = "rustfft", feature = "tfhe-fft"))]

//! Observe owned workspace allocations while live and immediately before release.
use primus_shape::PolyLength;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering},
};

#[cfg(feature = "rustfft")]
use primus_fft::RustFftTable;
#[cfg(feature = "tfhe-fft")]
use primus_fft::TfheFftTable;
use primus_fft::{Complex64, FftEngine, FftTable};
use zeroize::Zeroize;

struct ObservingAllocator;
thread_local! {
    static RECORDING: Cell<bool> = const { Cell::new(false) };
}
static POINTERS: [AtomicPtr<u8>; 2] = [const { AtomicPtr::new(ptr::null_mut()) }; 2];
static SIZES: [AtomicUsize; 2] = [const { AtomicUsize::new(0) }; 2];
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static RELEASED: AtomicUsize = AtomicUsize::new(0);
static ERASED: AtomicBool = AtomicBool::new(true);

fn record(data: *mut u8, layout: Layout) {
    if !data.is_null() && RECORDING.try_with(Cell::get).unwrap_or(false) {
        let index = ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        if let Some(pointer) = POINTERS.get(index) {
            pointer.store(data, Ordering::SeqCst);
            SIZES[index].store(layout.size(), Ordering::SeqCst);
        }
    }
}

// SAFETY: System retains ownership. Observation does not allocate or read
// freed memory. The fixture initializes every byte of the tracked buffers.
unsafe impl GlobalAlloc for ObservingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: layout is supplied by the caller as required by GlobalAlloc.
        let data = unsafe { System.alloc(layout) };
        record(data, layout);
        data
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same allocation contract, including the required zero fill.
        let data = unsafe { System.alloc_zeroed(layout) };
        record(data, layout);
        data
    }

    unsafe fn dealloc(&self, data: *mut u8, layout: Layout) {
        for pointer in &POINTERS {
            if pointer
                .compare_exchange(data, ptr::null_mut(), Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                // SAFETY: the initialized allocation is still live until
                // System.dealloc below; no other thread accesses this workspace.
                let bytes = unsafe { std::slice::from_raw_parts(data, layout.size()) };
                ERASED.fetch_and(bytes.iter().all(|&byte| byte == 0), Ordering::SeqCst);
                RELEASED.fetch_add(1, Ordering::SeqCst);
                break;
            }
        }
        // SAFETY: original System allocation and layout.
        unsafe { System.dealloc(data, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: ObservingAllocator = ObservingAllocator;

fn check_backend<Table: FftTable>(log_n: u32)
where
    Table::Workspace: Zeroize,
{
    let table = Table::new(PolyLength::new(1usize << log_n));
    ALLOCATIONS.store(0, Ordering::SeqCst);
    RELEASED.store(0, Ordering::SeqCst);
    ERASED.store(true, Ordering::SeqCst);
    RECORDING.set(true);
    let mut fft = FftEngine::new(&table);
    RECORDING.set(false);
    // Small RustFFT plans need no extra backend work buffer.
    let allocation_count = ALLOCATIONS.load(Ordering::SeqCst);
    assert!((1..=POINTERS.len()).contains(&allocation_count));

    // Seed all buffers, including backend work bytes a particular FFT plan
    // might not touch. All byte patterns are valid Complex64/f64 and u8 values.
    for (pointer, size) in POINTERS.iter().zip(&SIZES).take(allocation_count) {
        // SAFETY: these are the exclusive workspace's live allocations, with
        // no outstanding references into them. The recorded lengths are exact.
        unsafe {
            ptr::write_bytes(
                pointer.load(Ordering::SeqCst),
                0xA5,
                size.load(Ordering::SeqCst),
            );
        }
    }
    fft.zeroize_workspace();
    for (pointer, size) in POINTERS.iter().zip(&SIZES).take(allocation_count) {
        // SAFETY: initialized, still-live workspace storage with no mutation.
        let bytes = unsafe {
            std::slice::from_raw_parts(pointer.load(Ordering::SeqCst), size.load(Ordering::SeqCst))
        };
        assert!(bytes.iter().all(|&byte| byte == 0));
    }

    let input: Vec<u32> = (0..table.poly_length().get())
        .map(|i| (i as u32).wrapping_mul(0x12345))
        .collect();
    let mut fourier = vec![Complex64::default(); table.fourier_length()];
    let mut output = vec![0u32; table.poly_length().get()];
    for _ in 0..2 {
        fft.zeroize_workspace();
        fft.forward_as_torus(&input, &mut fourier);
        fft.backward_as_torus(&fourier, &mut output);
        assert_eq!(input, output);
    }
    // Inverse FFT has just repopulated workspace with nonzero phase data.
    drop(fft);
    assert_eq!(RELEASED.load(Ordering::SeqCst), allocation_count);
    assert!(
        ERASED.load(Ordering::SeqCst),
        "workspace was released without erasure"
    );
}

// Keep the shared allocation observations in one serial test.
#[test]
fn scratch_is_erased_and_reusable() {
    // Retain sub-alignment buffers and a plan with backend work storage.
    for log_n in [5, 10] {
        #[cfg(feature = "rustfft")]
        check_backend::<RustFftTable>(log_n);
        #[cfg(feature = "tfhe-fft")]
        check_backend::<TfheFftTable>(log_n);
    }
}
