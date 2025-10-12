#![no_std]

use core::sync::atomic::{AtomicU32, Ordering};

#[repr(C, align(64))]
struct VdsoData {
    seq: AtomicU32,     // seqlock: even=stable, odd=writer
    tsc_mul: u64,       // ns = ((tsc - tsc_base) * tsc_mul) >> tsc_shift
    tsc_shift: u32,
    tsc_base: u64,      // rdtsc at last update
    mono_base_ns: u64,  // CLOCK_MONOTONIC base
    real_base_ns: u64,  // CLOCK_REALTIME base
    flags: u32,         // future use
    _pad: u32,
}

impl const Default for VdsoData {
    fn default() -> Self {
        Self {
            seq: AtomicU32::new(0),
            tsc_mul: 0,
            tsc_shift: 0,
            tsc_base: 0,
            mono_base_ns: 0,
            real_base_ns: 0,
            flags: 0,
            _pad: 0,
        }
    }
}

static VDSO: VdsoData = VdsoData::default();

#[inline(always)]
fn rdtsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(not(target_arch = "x86_64"))]
    { 0 }
}

#[inline]
fn ns_from_tsc(delta_tsc: u64, mul: u64, shift: u32) -> u64 {
    (delta_tsc.saturating_mul(mul)) >> shift
}

// mul/shift so that ns ≈ cycles * 1e9 / tsc_hz with (cycles * mul) >> shift
fn compute_tsc_mult_shift(tsc_hz: u64) -> (u64, u32) {
    // Choose shift=32 for precision; mul = round((1e9 << shift) / tsc_hz)
    let shift: u32 = 32;
    let num = (1_000_000_000u128) << shift;
    let mul = (num + (tsc_hz as u128 / 2)) / (tsc_hz as u128);
    (mul as u64, shift)
}

// vDSO conversion with current TSC and bases
pub fn vdso_init(tsc_hz: u64, mono_ns: u64, real_ns: u64) {
    let (mul, shift) = compute_tsc_mult_shift(tsc_hz);
    let tsc_now = rdtsc();

    // seq write begin
    VDSO.seq.fetch_add(1, Ordering::Relaxed);
    // publish
    VDSO.tsc_mul = mul;
    VDSO.tsc_shift = shift;
    VDSO.tsc_base = tsc_now;
    VDSO.mono_base_ns = mono_ns;
    VDSO.real_base_ns = real_ns;
    // seq write end
    VDSO.seq.fetch_add(1, Ordering::Release);
}

// Update bases, typically from timer tick.
pub fn vdso_update(mono_ns: u64, real_ns: u64) {
    let tsc_now = rdtsc();
    VDSO.seq.fetch_add(1, Ordering::Relaxed);
    VDSO.tsc_base = tsc_now;
    VDSO.mono_base_ns = mono_ns;
    VDSO.real_base_ns = real_ns;
    VDSO.seq.fetch_add(1, Ordering::Release);
}

#[inline]
fn read_time_pair() -> (u64, u64, u64, u64, u32, u64) {
    loop {
        let s1 = VDSO.seq.load(Ordering::Acquire);
        if (s1 & 1) != 0 { continue; }

        // snapshot
        let tsc_mul = VDSO.tsc_mul;
        let tsc_shift = VDSO.tsc_shift;
        let tsc_base = VDSO.tsc_base;
        let mono_base_ns = VDSO.mono_base_ns;
        let real_base_ns = VDSO.real_base_ns;
        let tsc_now = rdtsc();

        let s2 = VDSO.seq.load(Ordering::Acquire);
        if s1 == s2 { return (tsc_mul, tsc_shift, tsc_base, mono_base_ns, s2, real_base_ns); }
    }
}

#[inline]
fn now_ns(base_ns: u64, tsc_now: u64, tsc_base: u64, mul: u64, shift: u32) -> u64 {
    let delta = tsc_now.saturating_sub(tsc_base);
    base_ns.saturating_add(ns_from_tsc(delta, mul, shift))
}

// Public fast paths

#[inline]
pub fn vdso_time_millis() -> u64 {
    let (mul, shift, base_tsc, mono_base, _s, _real_base) = read_time_pair();
    let tsc = rdtsc();
    now_ns(mono_base, tsc, base_tsc, mul, shift) / 1_000_000
}

#[inline]
pub fn vdso_time_nanos_monotonic() -> u64 {
    let (mul, shift, base_tsc, mono_base, _s, _real_base) = read_time_pair();
    let tsc = rdtsc();
    now_ns(mono_base, tsc, base_tsc, mul, shift)
}

#[inline]
pub fn vdso_time_nanos_realtime() -> u64 {
    let (mul, shift, base_tsc, _mono_base, _s, real_base) = read_time_pair();
    let tsc = rdtsc();
    now_ns(real_base, tsc, base_tsc, mul, shift)
}

// If an arch tick source is present, use it.
#[inline]
pub fn vdso_ticks() -> u64 {
    #[allow(unused)]
    {
        return crate::time::current_ticks();
    }
}

// Returns the kernel VA of the vDSO data.
pub fn vdso_data_ptr() -> *const () {
    &VDSO as *const VdsoData as *const ()
}
