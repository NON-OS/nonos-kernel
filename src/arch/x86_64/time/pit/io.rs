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

use super::{ports, command};
use super::types::{Channel, Mode, AccessMode};

#[inline]
pub(super) unsafe fn inb(port: u16) -> u8 {
    // SAFETY: Caller ensures port access is valid for PIT hardware.
    unsafe {
        let value: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nostack, preserves_flags, nomem)
        );
        value
    }
}

#[inline]
pub(super) unsafe fn outb(port: u16, value: u8) {
    // SAFETY: Caller ensures port access is valid for PIT hardware.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("al") value,
            in("dx") port,
            options(nostack, preserves_flags, nomem)
        );
    }
}

#[inline]
pub(super) fn io_delay() {
    // SAFETY: Port 0x80 is the POST diagnostic port, reading is safe for delay.
    unsafe {
        inb(0x80);
    }
}

pub(super) fn configure_channel_raw(channel: Channel, mode: Mode, divisor: u16) {
    let command_byte = channel.select_bits() | AccessMode::LowHigh.bits() | mode.bits();

    // SAFETY: Writing to PIT command and data ports to configure timer channel.
    unsafe {
        outb(ports::COMMAND, command_byte);
        io_delay();

        outb(channel.data_port(), (divisor & 0xFF) as u8);
        io_delay();

        outb(channel.data_port(), ((divisor >> 8) & 0xFF) as u8);
        io_delay();
    }
}

pub(super) fn read_channel_count(channel: Channel) -> u16 {
    let latch_command = channel.select_bits() | AccessMode::Latch.bits();

    // SAFETY: Reading PIT channel count via latch command.
    unsafe {
        outb(ports::COMMAND, latch_command);
        io_delay();

        let low = inb(channel.data_port());
        io_delay();

        let high = inb(channel.data_port());

        ((high as u16) << 8) | (low as u16)
    }
}

pub(super) fn read_channel_status(channel: Channel) -> u8 {
    // SAFETY: Reading PIT channel status via read-back command.
    unsafe {
        let readback = command::READ_BACK | command::READBACK_COUNT | channel.readback_bit();
        outb(ports::COMMAND, readback);
        io_delay();

        inb(channel.data_port())
    }
}
