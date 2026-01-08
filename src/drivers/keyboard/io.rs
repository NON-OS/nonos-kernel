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

use super::constants::*;
use core::hint::spin_loop;

const MAX_POLL_ITERATIONS: usize = 10000;

#[inline(always)]
pub unsafe fn inb(port: u16) -> u8 {
    // SAFETY: Caller ensures valid port.
    let mut v: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nostack, preserves_flags));
    v
}

#[inline(always)]
pub unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Caller ensures valid port.
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
}

pub fn wait_input_empty() {
    for _ in 0..MAX_POLL_ITERATIONS {
        // SAFETY: Reading status port.
        let s = unsafe { inb(KBD_STATUS) };
        if (s & STATUS_INPUT_FULL) == 0 {
            break;
        }
        spin_loop();
    }
}

pub fn wait_output_full() -> bool {
    for _ in 0..MAX_POLL_ITERATIONS {
        // SAFETY: Reading status port.
        let s = unsafe { inb(KBD_STATUS) };
        if (s & STATUS_OUTPUT_FULL) != 0 {
            return true;
        }
        spin_loop();
    }
    false
}

pub fn flush_output_buffer() {
    // SAFETY: Reading status and data ports to flush buffer.
    while unsafe { inb(KBD_STATUS) } & STATUS_OUTPUT_FULL != 0 {
        let _ = unsafe { inb(KBD_DATA) };
    }
}

pub fn i8042_init_best_effort() {
    flush_output_buffer();

    wait_input_empty();
    // SAFETY: Writing to data port to enable scanning.
    unsafe { outb(KBD_DATA, KBD_ENABLE_SCANNING) };

    if wait_output_full() {
        // SAFETY: Reading ACK response.
        let _ = unsafe { inb(KBD_DATA) };
    }
}

#[inline]
pub fn read_data_if_available() -> Option<u8> {
    // SAFETY: Reading status and data ports.
    let status = unsafe { inb(KBD_STATUS) };
    if (status & STATUS_OUTPUT_FULL) != 0 {
        Some(unsafe { inb(KBD_DATA) })
    } else {
        None
    }
}

pub fn send_keyboard_command(cmd: u8) -> bool {
    wait_input_empty();
    // SAFETY: Writing command to data port.
    unsafe { outb(KBD_DATA, cmd) };

    if wait_output_full() {
        // SAFETY: Reading response.
        let response = unsafe { inb(KBD_DATA) };
        return response == KBD_ACK;
    }
    false
}

pub fn send_keyboard_data(data: u8) -> bool {
    wait_input_empty();
    // SAFETY: Writing data to data port.
    unsafe { outb(KBD_DATA, data) };

    if wait_output_full() {
        // SAFETY: Reading response.
        let response = unsafe { inb(KBD_DATA) };
        return response == KBD_ACK;
    }
    false
}

pub fn update_leds(caps: bool, _num: bool, _scroll: bool) {
    wait_input_empty();
    // SAFETY: Writing LED command.
    unsafe { outb(KBD_DATA, KBD_SET_LEDS) };
    if wait_output_full() {
        // SAFETY: Reading ACK.
        let _ = unsafe { inb(KBD_DATA) };
    }

    wait_input_empty();
    let mask = if caps { LED_CAPS_LOCK } else { 0 };
    // SAFETY: Writing LED mask.
    unsafe { outb(KBD_DATA, mask) };
    if wait_output_full() {
        // SAFETY: Reading ACK.
        let _ = unsafe { inb(KBD_DATA) };
    }
}

#[inline(always)]
pub fn send_eoi() {
    crate::arch::x86_64::interrupt::apic::send_eoi();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_led_mask_values() {
        assert_eq!(LED_SCROLL_LOCK, 0b001);
        assert_eq!(LED_NUM_LOCK, 0b010);
        assert_eq!(LED_CAPS_LOCK, 0b100);
    }

    #[test]
    fn test_status_bits() {
        assert_eq!(STATUS_OUTPUT_FULL, 0x01);
        assert_eq!(STATUS_INPUT_FULL, 0x02);
    }
}
