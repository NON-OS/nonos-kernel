// ui/keyboard.rs
//
// PS/2 scancode -> ASCII (US layout), IRQ-safe ring buffer.
// - Non-blocking push from IRQ handler; blocking getchar for CLI/TUI.
// - Extend to USB HID later via a unified input bus.

#![allow(dead_code)]

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

const CAP: usize = 512;
static RING: Mutex<[u8; CAP]> = Mutex::new([0; CAP]);
static HEAD: AtomicUsize = AtomicUsize::new(0);
static TAIL: AtomicUsize = AtomicUsize::new(0);

#[inline] fn adv(i: usize) -> usize { (i + 1) % CAP }

pub fn getchar_blocking() -> u8 {
    loop {
        if let Some(b) = try_getchar() { return b; }
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
    }
}

pub fn try_getchar() -> Option<u8> {
    let h = HEAD.load(Ordering::Acquire);
    let t = TAIL.load(Ordering::Acquire);
    if h == t { return None; }
    let b = RING.lock()[t];
    TAIL.store(adv(t), Ordering::Release);
    Some(b)
}

/// IRQ handler should call this with translated ASCII (ignore non-printables).
pub fn push_key(b: u8) {
    let h = HEAD.load(Ordering::Relaxed);
    let n = adv(h);
    if n == TAIL.load(Ordering::Relaxed) { return; } // drop on overflow
    RING.lock()[h] = b;
    HEAD.store(n, Ordering::Release);
}

/// Example scan-to-ascii (very partial; replace with proper map).
pub fn scancode_to_ascii(sc: u8) -> Option<u8> {
    // crude: digits/letters only; extend with shift state, etc.
    const MAP: [u8; 0x60] = [0; 0x60];
    if (sc as usize) < MAP.len() {
        let c = MAP[sc as usize];
        if c != 0 { return Some(c); }
    }
    None
}
