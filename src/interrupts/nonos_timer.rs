//! Timer integration 

#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};
use spin::Once;

type TickHook = fn();

static TICKS: AtomicU64 = AtomicU64::new(0);
static HOOK: Once<spin::RwLock<Option<TickHook>>> = Once::new();

pub fn init() {
    HOOK.call_once(|| spin::RwLock::new(None));
    // arch timer (kept optional)
    #[cfg(any())]
    {
        crate::arch::x86_64::time::timer::init();
    }
}

pub fn set_tick_hook(h: TickHook) {
    if let Some(lock) = HOOK.get() {
        *lock.write() = Some(h);
    }
}

#[inline]
pub fn tick_count() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Called by timer ISR. 
pub fn on_timer_interrupt() {
    TICKS.fetch_add(1, Ordering::Relaxed);
    if let Some(lock) = HOOK.get() {
        if let Some(cb) = *lock.read() {
            cb();
        }
    }
}
