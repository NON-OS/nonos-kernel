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

use crate::display::{log_hash, log_hex, log_size};

pub fn display_kernel_info(data: &[u8]) {
    log_size(b"kernel.bin ", data.len());
    log_hex(b"kernel base ", data.as_ptr() as u64);
    log_hex(b"kernel end  ", (data.as_ptr() as u64) + (data.len() as u64));
    if data.len() >= 8 {
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&data[..8]);
        log_hash(b"ELF header  ", &magic);
    }
}
