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

// Direct COM1 byte writer used after UEFI Boot Services exit.
// Real `out al, dx` lives in `arch::x86_64::asm::com1_out.S`.

unsafe extern "C" {
    fn nonos_arch_com1_out(byte: u8);
}

#[inline(always)]
pub fn com1_out(byte: u8) {
    unsafe { nonos_arch_com1_out(byte) }
}

// Emit a short bracketed marker followed by CR/LF. Used by the
// late-stage handoff path to localize hangs that happen after
// UEFI logging is gone.
pub fn com1_marker(tag: &[u8]) {
    com1_out(b'[');
    for &b in tag {
        com1_out(b);
    }
    com1_out(b']');
    com1_out(b'\r');
    com1_out(b'\n');
}
