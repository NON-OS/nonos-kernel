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

use crate::sys::serial::Line;

use super::nmi_record::record;
use super::nmi_source::{identify_nmi_source, NmiSource};

pub fn handle(frame: InterruptStackFrame) {
    /*
     * The kernel's own NMIs first: a fatal halt of the machine, or a TLB
     * shootdown round re-sent to a cpu that did not take the vector. That
     * step is NMI-safe; what follows counts the NMI and tries the serial
     * line, and is reached for an NMI nothing in the kernel sent, or when a
     * hardware cause is latched in port B alongside ours, so a coincident
     * parity or channel check is not lost.
     */
    if cfg!(feature = "nonos-smp")
        && crate::smp::nmi::on_nmi()
        && matches!(identify_nmi_source(), NmiSource::Unknown)
    {
        return;
    }
    let rip = frame.instruction_pointer.as_u64();
    let source = identify_nmi_source();
    record(source, rip);
    let mut line = Line::new();
    line.str(b"NMI ").str(describe(source)).str(b" rip=");
    if crate::security::is_production_mode() {
        line.str(b"[ADDR]");
    } else {
        line.hex(rip);
    }
    line.end_try();
}

fn describe(source: NmiSource) -> &'static [u8] {
    match source {
        NmiSource::MemoryParity => b"memory parity error, memory subsystem may be unstable",
        NmiSource::IoChannelCheck => b"I/O channel check, peripheral failure possible",
        NmiSource::Watchdog => b"watchdog timeout",
        NmiSource::Unknown => b"unknown source",
    }
}
