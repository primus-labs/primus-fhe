//! Observe secret storage immediately before its allocator releases it.

use primus_lattice::GlweDimension;
use primus_shape::PolyLength;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    convert::Infallible,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering},
};

use primus_distr::SecretKeySampler;
use primus_fft::Complex64;
use primus_glwe::{
    FourierGlweSecretKey, GlweSecretKey, GlweSize, NttGlweSecretKey, SecretKeyDistr,
};
use rand::{TryCryptoRng, TryRng};

struct ObservingAllocator;
thread_local! {
    static CAPTURE_NEXT: Cell<bool> = const { Cell::new(false) };
}
static WATCHED: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static LENGTH: AtomicUsize = AtomicUsize::new(0);
static ERASED: AtomicBool = AtomicBool::new(false);

// SAFETY: allocation and deallocation are delegated unchanged to System. The
// observer only reads a watched allocation before System releases its storage.
unsafe impl GlobalAlloc for ObservingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies the layout required by GlobalAlloc.
        let data = unsafe { System.alloc(layout) };
        if !data.is_null()
            && CAPTURE_NEXT
                .try_with(|capture| capture.replace(false))
                .unwrap_or(false)
        {
            WATCHED.store(data, Ordering::SeqCst);
            LENGTH.store(layout.size(), Ordering::SeqCst);
        }
        data
    }

    unsafe fn dealloc(&self, data: *mut u8, layout: Layout) {
        if WATCHED
            .compare_exchange(data, ptr::null_mut(), Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let len = LENGTH.load(Ordering::SeqCst);
            let mut erased = len <= layout.size();
            for index in 0..len.min(layout.size()) {
                // SAFETY: data is still allocated, and the test only watches
                // initialized integer/complex values within this allocation.
                erased &= unsafe { ptr::read_volatile(data.add(index)) } == 0;
            }
            ERASED.store(erased, Ordering::SeqCst);
        }
        // SAFETY: data/layout are the original allocation passed by the caller.
        unsafe { System.dealloc(data, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservingAllocator = ObservingAllocator;

// Test-only source: write 32 nonzero coefficients before forcing unwinding.
struct PanicAfterOneWord(bool);
impl TryRng for PanicAfterOneWord {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        assert!(
            !std::mem::replace(&mut self.0, true),
            "sampling interrupted"
        );
        Ok(u32::MAX)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        panic!("unexpected u64 draw");
    }

    fn try_fill_bytes(&mut self, _output: &mut [u8]) -> Result<(), Infallible> {
        panic!("unexpected byte draw");
    }
}
impl TryCryptoRng for PanicAfterOneWord {}

fn watch(data: *const u8, len: usize) {
    ERASED.store(false, Ordering::SeqCst);
    LENGTH.store(len, Ordering::SeqCst);
    WATCHED.store(data.cast_mut(), Ordering::SeqCst);
}

fn assert_erased() {
    assert!(
        WATCHED.load(Ordering::SeqCst).is_null(),
        "secret allocation was not released"
    );
    assert!(
        ERASED.load(Ordering::SeqCst),
        "secret allocation was released without erasure"
    );
}

fn assert_erased_on_drop<K>(key: K, data: *const u8, len: usize) {
    watch(data, len);
    drop(key);
    assert_erased();
}

// Imports take ownership even when layout validation rejects the buffer.
fn assert_erased_on_rejection<K>(data: *const u8, len: usize, import: impl FnOnce() -> K) {
    watch(data, len);
    assert!(catch_unwind(AssertUnwindSafe(import)).is_err());
    assert_erased();
}

// Keep allocator observations serial: all cases share the watched allocation.
#[test]
fn secret_storage_is_erased_on_drop_and_unwind() {
    let size = GlweSize::new(GlweDimension::new(1), PolyLength::new(32));
    let mut coefficients = vec![1i32; 2 * size.mask_len()];
    let data = coefficients.as_ptr().cast();
    let len = size_of_val(coefficients.as_slice());
    coefficients.truncate(size.mask_len());
    assert_erased_on_drop(
        GlweSecretKey::<u32>::new(coefficients, size, SecretKeyDistr::UniformBinary),
        data,
        len,
    );

    let mut ntt = vec![1u32; 2 * size.mask_len()];
    let data = ntt.as_ptr().cast();
    let len = size_of_val(ntt.as_slice());
    ntt.truncate(size.mask_len());
    assert_erased_on_drop(
        NttGlweSecretKey::new(
            ntt,
            size,
            SecretKeyDistr::UniformBinary,
            primus_modulus::BarrettModulus::new(257),
        ),
        data,
        len,
    );

    // Keep an initialized, truncated tail: rejection must also erase capacity
    // that once held coefficients, not only the invalid logical prefix.
    let mut invalid_coefficients = vec![1i32; 2 * size.mask_len()];
    let data = invalid_coefficients.as_ptr().cast();
    let len = size_of_val(invalid_coefficients.as_slice());
    invalid_coefficients.truncate(size.mask_len() - 1);
    assert_erased_on_rejection(data, len, || {
        GlweSecretKey::<u32>::new(invalid_coefficients, size, SecretKeyDistr::UniformBinary)
    });

    let mut invalid_ntt = vec![1u32; 2 * size.mask_len()];
    let data = invalid_ntt.as_ptr().cast();
    let len = size_of_val(invalid_ntt.as_slice());
    invalid_ntt.truncate(size.mask_len() - 1);
    assert_erased_on_rejection(data, len, || {
        NttGlweSecretKey::new(
            invalid_ntt,
            size,
            SecretKeyDistr::UniformBinary,
            primus_modulus::BarrettModulus::new(257),
        )
    });

    let mut fourier = vec![Complex64::new(1.0, 1.0); 2 * size.fourier_mask_len()];
    let data = fourier.as_ptr().cast();
    let len = size_of_val(fourier.as_slice());
    fourier.truncate(size.fourier_mask_len());
    assert_erased_on_drop(
        FourierGlweSecretKey::new(fourier, size, SecretKeyDistr::UniformBinary),
        data,
        len,
    );

    let mut invalid_fourier = vec![Complex64::new(1.0, 1.0); 2 * size.fourier_mask_len()];
    let data = invalid_fourier.as_ptr().cast();
    let len = size_of_val(invalid_fourier.as_slice());
    invalid_fourier.truncate(size.fourier_mask_len() - 1);
    assert_erased_on_rejection(data, len, || {
        FourierGlweSecretKey::new(invalid_fourier, size, SecretKeyDistr::UniformBinary)
    });

    let sampler = SecretKeySampler::<u32>::new(SecretKeyDistr::UniformBinary);
    let size = GlweSize::new(GlweDimension::new(1), PolyLength::new(64));
    ERASED.store(false, Ordering::SeqCst);
    CAPTURE_NEXT.set(true);
    let result = catch_unwind(AssertUnwindSafe(|| {
        // The first allocation is the fully initialized coefficient buffer.
        let _ = GlweSecretKey::generate(size, &sampler, &mut PanicAfterOneWord(false));
    }));
    CAPTURE_NEXT.set(false);
    assert!(result.is_err());
    assert!(WATCHED.load(Ordering::SeqCst).is_null());
    assert!(
        ERASED.load(Ordering::SeqCst),
        "partial sample was not erased"
    );
}
