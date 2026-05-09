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

//! Resolve the page-table root that the page walk should use. For a
//! syscall handler the caller is the user process, so the process's
//! recorded `page_table_root` is the right answer. For a kernel-side
//! caller without a process context the active CR3 is read through
//! the arch helper. There is no inline asm at this layer.

use crate::arch::x86_64::paging::read_cr3;
use crate::context::{get_current_context, ExecutionContext};
use crate::memory::paging::constants::PTE_ADDR_MASK;
use crate::usercopy::error::UsercopyError;

pub(super) fn page_table_root() -> Result<u64, UsercopyError> {
    match get_current_context() {
        ExecutionContext::Process(ctx) => Ok(ctx.page_table_root),
        ExecutionContext::Kernel(_) => Ok(read_cr3() & PTE_ADDR_MASK),
        ExecutionContext::None => Err(UsercopyError::NoProcessContext),
    }
}
