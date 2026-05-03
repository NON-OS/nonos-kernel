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

/* reads real system state for audit log */

use crate::arch::x86_64::cpu;
use crate::display::framebuffer::{COLOR_ACCENT, COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW};
use crate::mem::heap;
use crate::shell::output::print_line;

pub fn cmd_audit() {
    print_line(b"Security Audit Log:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    let features = cpu::features();
    let mem_ok = heap::is_init();

    print_line(b"[INFO]  System boot initiated", COLOR_TEXT);
    print_status(b"Memory isolation", mem_ok);
    print_status(b"SMEP", features.smep);
    print_status(b"SMAP", features.smap);
    print_status(b"NX bit", features.nx);

    let nym_ready = crate::network::nym::get_nym_client().is_ok();
    if nym_ready {
        print_line(b"[INFO]  NYM Mixnet: READY", COLOR_ACCENT);
    } else {
        print_line(b"[INFO]  NYM Mixnet: STANDBY", COLOR_YELLOW);
    }

    print_line(b"", COLOR_TEXT);
    print_line(b"Audit log stored in RAM only", COLOR_YELLOW);
}

fn print_status(name: &[u8], ok: bool) {
    let mut line = [b' '; 40];
    line[0..8].copy_from_slice(b"[INFO]  ");
    let n = name.len().min(20);
    line[8..8 + n].copy_from_slice(&name[..n]);
    line[30..32].copy_from_slice(b": ");

    if ok {
        line[32..38].copy_from_slice(b"ACTIVE");
        print_line(&line[..38], COLOR_GREEN);
    } else {
        line[32..40].copy_from_slice(b"INACTIVE");
        print_line(&line[..40], COLOR_RED);
    }
}
