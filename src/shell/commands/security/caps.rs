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

/* queries real CPU capabilities via CPUID */

use crate::arch::x86_64::cpu;
use crate::display::framebuffer::{COLOR_GREEN, COLOR_TEXT_DIM, COLOR_TEXT_WHITE};
use crate::shell::output::print_line;

pub fn cmd_caps() {
    print_line(b"CPU Capabilities:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    let f = cpu::features();

    print_cap(b"SSE", f.sse);
    print_cap(b"SSE2", f.sse2);
    print_cap(b"SSE3", f.sse3);
    print_cap(b"SSE4.1", f.sse4_1);
    print_cap(b"SSE4.2", f.sse4_2);
    print_cap(b"AVX", f.avx);
    print_cap(b"AVX2", f.avx2);
    print_cap(b"AES-NI", f.aes_ni);
    print_cap(b"RDRAND", f.rdrand);
    print_cap(b"RDSEED", f.rdseed);
    print_cap(b"SHA", f.sha);
    print_cap(b"SMEP", f.smep);
    print_cap(b"SMAP", f.smap);
}

fn print_cap(name: &[u8], ok: bool) {
    let mut line = [b' '; 28];
    line[0..2].copy_from_slice(b"  ");
    let n = name.len().min(12);
    line[2..2 + n].copy_from_slice(&name[..n]);

    if ok {
        line[16..25].copy_from_slice(b"AVAILABLE");
        print_line(&line[..25], COLOR_GREEN);
    } else {
        line[16..27].copy_from_slice(b"UNAVAILABLE");
        print_line(&line[..27], COLOR_TEXT_DIM);
    }
}
