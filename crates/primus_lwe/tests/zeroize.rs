//! Observe partially sampled secrets immediately before deallocation on unwind.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    convert::Infallible,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};

use primus_lwe::{LweDimension, LweEncryptionParameters, LweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use rand::{TryCryptoRng, TryRng};

struct ObservingAllocator;
thread_local! {
    static CAPTURE_NEXT: Cell<bool> = const { Cell::new(false) };
}
static WATCHED: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static ERASED: AtomicBool = AtomicBool::new(false);

// SAFETY: forward original pointers/layouts to System. Only read the first u64
// before release; the fixture finishes writing it before its RNG panics.
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
        }
        data
    }

    unsafe fn dealloc(&self, data: *mut u8, layout: Layout) {
        if WATCHED
            .compare_exchange(data, ptr::null_mut(), Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            // The remaining capacity may be uninitialized in a regressed
            // collecting sampler, so never inspect beyond the completed sample.
            let len = size_of::<u64>();
            let mut erased = len <= layout.size();
            for index in 0..len.min(layout.size()) {
                // SAFETY: the completed sample is initialized and still allocated.
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

// Binary writes 32 ones after the first u32; CDT writes a nonzero tail sample
// after the first u64. The next draw fails after that secret prefix is stored.
struct PanicAfterOneWord(bool);
impl PanicAfterOneWord {
    fn draw(&mut self) {
        assert!(
            !std::mem::replace(&mut self.0, true),
            "sampling interrupted"
        );
    }
}
impl TryRng for PanicAfterOneWord {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        self.draw();
        Ok(u32::MAX)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.draw();
        Ok(u64::MAX)
    }

    fn try_fill_bytes(&mut self, _output: &mut [u8]) -> Result<(), Infallible> {
        panic!("unexpected byte draw");
    }
}
impl TryCryptoRng for PanicAfterOneWord {}

// One test keeps the allocator's watched pointer serial across both samplers.
#[test]
fn key_generation_erases_partial_binary_and_gaussian_samples_on_unwind() {
    for distribution in [SecretKeyDistr::UniformBinary, SecretKeyDistr::gaussian(3.2)] {
        let params = LweEncryptionParameters::new(
            LweDimension::new(64),
            BarrettModulus::new(1009u64),
            distribution,
            0.7,
        );
        ERASED.store(false, Ordering::SeqCst);
        CAPTURE_NEXT.set(true);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = LweSecretKey::generate(&params, &mut PanicAfterOneWord(false));
        }));
        CAPTURE_NEXT.set(false);
        assert!(result.is_err());
        assert!(
            WATCHED.load(Ordering::SeqCst).is_null(),
            "secret was not released"
        );
        assert!(
            ERASED.load(Ordering::SeqCst),
            "partial {distribution:?} sample was not erased"
        );
    }
}
