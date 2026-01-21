// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};
use super::cpuid::{cpuid, cpuid_max_leaf};
use super::control::{lfence, pause};
use super::tsc::rdtsc;

const PIT_FREQUENCY: u64 = 1_193_182;
const CALIBRATE_MS: u64 = 50;
const PIT_CHANNEL_0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;

static TSC_FREQUENCY: AtomicU64 = AtomicU64::new(0);
static CORE_FREQUENCY: AtomicU64 = AtomicU64::new(0);

fn detect_tsc_frequency_cpuid_15h() -> Option<u64> {
    let max_leaf = cpuid_max_leaf();
    if max_leaf < 0x15 {
        return None;
    }

    let (eax, ebx, ecx, _) = cpuid(0x15);
    let denominator = eax;
    let numerator = ebx;
    let crystal_freq = ecx;

    if denominator == 0 || numerator == 0 {
        return None;
    }

    let freq = if crystal_freq != 0 {
        (crystal_freq as u64 * numerator as u64) / denominator as u64
    } else {
        return None;
    };

    Some(freq)
}

fn detect_frequency_cpuid_16h() -> Option<u64> {
    let max_leaf = cpuid_max_leaf();
    if max_leaf < 0x16 {
        return None;
    }

    let (eax, _, _, _) = cpuid(0x16);
    let base_mhz = eax & 0xFFFF;

    if base_mhz > 0 {
        Some((base_mhz as u64) * 1_000_000)
    } else {
        None
    }
}

#[inline]
unsafe fn outb(port: u16, value: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

fn calibrate_tsc_with_pit() -> u64 {
    let pit_count = (PIT_FREQUENCY * CALIBRATE_MS) / 1000;

    unsafe {
        outb(PIT_COMMAND, 0x30);
        outb(PIT_CHANNEL_0, (pit_count & 0xFF) as u8);
        outb(PIT_CHANNEL_0, ((pit_count >> 8) & 0xFF) as u8);

        lfence();
        let tsc_start = rdtsc();

        loop {
            outb(PIT_COMMAND, 0xE2);
            let status = inb(PIT_CHANNEL_0);
            if (status & 0x80) != 0 {
                break;
            }
            pause();
        }

        lfence();
        let tsc_end = rdtsc();

        let elapsed = tsc_end.saturating_sub(tsc_start);
        let freq = (elapsed * 1000) / CALIBRATE_MS;

        if freq >= 500_000_000 && freq <= 6_000_000_000 {
            freq
        } else {
            2_400_000_000
        }
    }
}

pub fn tsc_frequency() -> u64 {
    let freq = TSC_FREQUENCY.load(Ordering::Relaxed);
    if freq > 0 {
        return freq;
    }

    if let Some(f) = detect_tsc_frequency_cpuid_15h() {
        TSC_FREQUENCY.store(f, Ordering::Relaxed);
        return f;
    }

    if let Some(f) = detect_frequency_cpuid_16h() {
        TSC_FREQUENCY.store(f, Ordering::Relaxed);
        return f;
    }

    let f = calibrate_tsc_with_pit();
    TSC_FREQUENCY.store(f, Ordering::Relaxed);
    f
}

pub fn core_frequency() -> u64 {
    let freq = CORE_FREQUENCY.load(Ordering::Relaxed);
    if freq > 0 {
        return freq;
    }

    if let Some(f) = detect_frequency_cpuid_16h() {
        CORE_FREQUENCY.store(f, Ordering::Relaxed);
        return f;
    }

    let f = tsc_frequency();
    CORE_FREQUENCY.store(f, Ordering::Relaxed);
    f
}

pub fn get_tsc_frequency() -> u64 {
    TSC_FREQUENCY.load(Ordering::Relaxed)
}

pub fn get_core_frequency() -> u64 {
    CORE_FREQUENCY.load(Ordering::Relaxed)
}
