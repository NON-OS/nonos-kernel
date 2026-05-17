use core::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);

pub fn next() -> u64 {
    NEXT.fetch_add(1, Ordering::Relaxed)
}
