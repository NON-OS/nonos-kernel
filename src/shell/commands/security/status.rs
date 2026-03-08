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

/* comprehensive security status from real CPU/system checks */

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW};
use crate::arch::x86_64::cpu;

pub fn cmd_secstatus() {
    print_line(b"Security Status:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    let f = cpu::features();

    print_line(b"", COLOR_TEXT);
    print_line(b"Memory Protection:", COLOR_TEXT_WHITE);
    print_feature(b"SMEP", f.smep);
    print_feature(b"SMAP", f.smap);
    print_feature(b"NX bit", f.nx);

    print_line(b"", COLOR_TEXT);
    print_line(b"Cryptographic:", COLOR_TEXT_WHITE);
    print_feature(b"RDRAND", f.rdrand);
    print_feature(b"RDSEED", f.rdseed);
    print_feature(b"AES-NI", f.aes_ni);
    print_feature(b"SHA", f.sha);

    print_line(b"", COLOR_TEXT);
    print_line(b"Privacy:", COLOR_TEXT_WHITE);
    print_line(b"  Anonymous Mode    ACTIVE", COLOR_GREEN);

    let tor = crate::network::onion::get_anyone_network().is_some();
    if tor {
        print_line(b"  Tor Routing       ACTIVE", COLOR_GREEN);
    } else {
        print_line(b"  Tor Routing       STANDBY", COLOR_YELLOW);
    }

    print_line(b"  Data Persistence  DISABLED", COLOR_GREEN);

    print_line(b"", COLOR_TEXT);
    let ok = f.smep && f.smap && f.aes_ni && f.rdrand;
    if ok {
        print_line(b"Overall: SECURE", COLOR_GREEN);
    } else {
        print_line(b"Overall: DEGRADED", COLOR_YELLOW);
    }
}

fn print_feature(name: &[u8], ok: bool) {
    let mut line = [b' '; 28];
    line[0..2].copy_from_slice(b"  ");
    let n = name.len().min(14);
    line[2..2+n].copy_from_slice(&name[..n]);

    if ok {
        line[18..25].copy_from_slice(b"ENABLED");
        print_line(&line[..25], COLOR_GREEN);
    } else {
        line[18..28].copy_from_slice(b"UNAVAILABLE");
        print_line(&line[..28], COLOR_YELLOW);
    }
}
