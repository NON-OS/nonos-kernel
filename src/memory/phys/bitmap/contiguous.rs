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

use super::bit_ops::bit_test;

pub(in crate::memory::phys) unsafe fn find_contiguous_free(
    ptr: *mut u8,
    total: usize,
    count: usize,
) -> Option<usize> {
    unsafe {
        if count == 0 || count > total {
            return None;
        }

        let mut run_start = 0usize;
        let mut run_length = 0usize;

        for i in 0..total {
            if !bit_test(ptr, i) {
                if run_length == 0 {
                    run_start = i;
                }
                run_length += 1;

                if run_length >= count {
                    return Some(run_start);
                }
            } else {
                run_length = 0;
            }
        }

        None
    }
}
