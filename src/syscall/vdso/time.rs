// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::sync::atomic::{AtomicU32, Ordering};
use spin::Once;

#[repr(C, align(64))]
struct VdsoData {
    seq: AtomicU32,
    tsc_mul: u64,
    tsc_shift: u32,
    tsc_base: u64,
    mono_base_ns: u64,
    real_base_ns: u64,
    flags: u32,
    _pad: u32,
}

impl Default for VdsoData {
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

static VDSO: Once<VdsoData> = Once::new();

fn get_vdso() -> &'static VdsoData {
    VDSO.call_once(|| VdsoData::default())
}

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

fn compute_tsc_mult_shift(tsc_hz: u64) -> (u64, u32) {
    let shift: u32 = 32;
    let num = (1_000_000_000u128) << shift;
    let mul = (num + (tsc_hz as u128 / 2)) / (tsc_hz as u128);
    (mul as u64, shift)
}

pub fn vdso_init(tsc_hz: u64, mono_ns: u64, real_ns: u64) {
    let (mul, shift) = compute_tsc_mult_shift(tsc_hz);
    let tsc_now = rdtsc();

    get_vdso().seq.fetch_add(1, Ordering::Relaxed);
    unsafe {
        let vdso_ptr = get_vdso() as *const VdsoData as *mut VdsoData;
        (*vdso_ptr).tsc_mul = mul;
        (*vdso_ptr).tsc_shift = shift;
        (*vdso_ptr).tsc_base = tsc_now;
        (*vdso_ptr).mono_base_ns = mono_ns;
        (*vdso_ptr).real_base_ns = real_ns;
    }
    get_vdso().seq.fetch_add(1, Ordering::Release);
}

pub fn vdso_update(mono_ns: u64, real_ns: u64) {
    let tsc_now = rdtsc();
    get_vdso().seq.fetch_add(1, Ordering::Relaxed);
    unsafe {
        let vdso_ptr = get_vdso() as *const VdsoData as *mut VdsoData;
        (*vdso_ptr).tsc_base = tsc_now;
        (*vdso_ptr).mono_base_ns = mono_ns;
        (*vdso_ptr).real_base_ns = real_ns;
    }
    get_vdso().seq.fetch_add(1, Ordering::Release);
}

#[inline]
fn read_time_pair() -> (u64, u32, u64, u64, u32, u64) {
    loop {
        let s1 = get_vdso().seq.load(Ordering::Acquire);
        if (s1 & 1) != 0 { continue; }

        let tsc_mul = get_vdso().tsc_mul;
        let tsc_shift = get_vdso().tsc_shift;
        let tsc_base = get_vdso().tsc_base;
        let mono_base_ns = get_vdso().mono_base_ns;
        let real_base_ns = get_vdso().real_base_ns;
        core::sync::atomic::fence(Ordering::Acquire);

        let s2 = get_vdso().seq.load(Ordering::Acquire);
        if s1 == s2 { return (tsc_mul, tsc_shift, tsc_base, mono_base_ns, s2, real_base_ns); }
    }
}

#[inline]
fn now_ns(base_ns: u64, tsc_now: u64, tsc_base: u64, mul: u64, shift: u32) -> u64 {
    let delta = tsc_now.saturating_sub(tsc_base);
    base_ns.saturating_add(ns_from_tsc(delta, mul, shift))
}

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

#[inline]
pub fn vdso_ticks() -> u64 {
    #[allow(unused)]
    {
        return crate::time::current_ticks();
    }
}

pub fn vdso_data_ptr() -> *const () {
    get_vdso() as *const VdsoData as *const ()
}
