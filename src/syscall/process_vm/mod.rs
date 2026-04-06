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

pub mod access;
pub mod copy;
pub mod iovec;
pub mod readv;
pub mod translate;
pub mod writev;

pub use access::{check_process_access, has_ptrace_permission, is_same_address_space, get_target_cr3, validate_remote_range};
pub use copy::{copy_from_remote, copy_to_remote, copy_byte_from_remote, copy_byte_to_remote, zero_remote};
pub use iovec::{IoVec, IOV_MAX, validate_iovec, total_iovec_len, count_nonempty, copy_from_user_iovec, advance_iovec};
pub use readv::sys_process_vm_readv;
pub use translate::{translate_with_cr3, is_writable_with_cr3, phys_to_virt};
pub use writev::sys_process_vm_writev;
