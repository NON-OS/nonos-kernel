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

// Zero the BSS tail of a PT_LOAD segment: the bytes that exist in
// `p_memsz` but not in `p_filesz`. Required for `.bss` and any
// trailing zero-init storage past the on-disk image.
//
// SAFETY: same constraints as `copy_payload`. Caller has already
// loaded the file portion at `dst_phys..dst_phys+filled_len`.
pub unsafe fn zero_tail(dst_phys: u64, filled_len: u64, total_len: u64) {
    if total_len <= filled_len {
        return;
    }
    let zero_at = dst_phys + filled_len;
    let zero_len = (total_len - filled_len) as usize;
    core::ptr::write_bytes(zero_at as *mut u8, 0, zero_len);
}
