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

use x86_64::structures::idt::InterruptStackFrame;
use x86_64::instructions::port::Port;

use super::context::{log_exception, ExceptionContext};

/// System control port A - used for system reset and A20 gate control
pub const SYSTEM_CONTROL_PORT_A: u16 = 0x92;
/// System control port B - used for NMI source identification
pub const SYSTEM_CONTROL_PORT_B: u16 = 0x61;

#[derive(Debug, Clone, Copy)]
pub enum NmiSource {
    MemoryParity,
    IoChannelCheck,
    Watchdog,
    Unknown,
}

pub fn handle(frame: InterruptStackFrame) {
    let ctx = ExceptionContext::from_frame(&frame);
    log_exception("NMI", &ctx);

    let source = identify_nmi_source();
    handle_nmi_source(source, &ctx);
}

fn identify_nmi_source() -> NmiSource {
    // SAFETY: Reading system control port B to determine NMI source
    let status = unsafe {
        let mut port = Port::<u8>::new(SYSTEM_CONTROL_PORT_B);
        port.read()
    };

    if (status & 0x80) != 0 {
        NmiSource::MemoryParity
    } else if (status & 0x40) != 0 {
        NmiSource::IoChannelCheck
    } else {
        NmiSource::Unknown
    }
}

fn handle_nmi_source(source: NmiSource, _ctx: &ExceptionContext) {
    match source {
        NmiSource::MemoryParity => {
            crate::log::logger::log_critical("NMI: Memory parity error detected");
            handle_memory_error();
        }
        NmiSource::IoChannelCheck => {
            crate::log::logger::log_critical("NMI: I/O channel check error");
            handle_io_error();
        }
        NmiSource::Watchdog => {
            crate::log::logger::log_warning!("NMI: Watchdog timeout");
            handle_watchdog();
        }
        NmiSource::Unknown => {
            crate::log::logger::log_warning!("NMI: Unknown source");
        }
    }
}

fn handle_memory_error() {
    crate::log::logger::log_critical("Memory subsystem error - system may be unstable");
}

fn handle_io_error() {
    crate::log::logger::log_critical("I/O subsystem error - peripheral failure possible");
}

fn handle_watchdog() {
    crate::log::logger::log_warning!("System watchdog triggered");
}
