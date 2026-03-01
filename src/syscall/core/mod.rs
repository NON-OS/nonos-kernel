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

mod legacy;
mod wrappers;

pub use legacy::{
    legacy_handle_syscall2, legacy_handle_syscall3, legacy_handle_syscall4,
    legacy_handle_syscall5, legacy_handle_syscall6, nonos_legacy_syscall_entry,
};

pub use wrappers::{
    sys_open, sys_read, sys_write, sys_close, sys_stat, sys_fstat,
    sys_lseek, sys_mkdir, sys_rmdir, sys_unlink, sys_rename,
};
