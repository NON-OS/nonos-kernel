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

use super::control::lfence;
use super::control_intr::pause;
use super::tsc::rdtsc;
use core::arch::asm;

const PIT_FREQUENCY: u64 = 1_193_182;
const CALIBRATE_MS: u64 = 50;
const PIT_CHANNEL_0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;

#[inline]
unsafe fn outb(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack, preserves_flags));
    }
    value
}

pub fn calibrate_tsc_with_pit() -> u64 {
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
