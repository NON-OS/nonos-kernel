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

pub mod helpers;
pub mod path;
pub mod stat;
pub mod dir;
pub mod create;
pub mod link;
pub mod perm;
pub mod open;
pub mod statfs;
pub mod mount;

pub use helpers::{read_user_string, resolve_path_at};
pub use path::{handle_getcwd, handle_chdir};
pub use stat::{handle_access, handle_readlink, handle_lstat};
pub use dir::{handle_getdents64, handle_getdents, handle_fchdir};
pub use create::{handle_mkdirat, handle_unlinkat, handle_renameat, handle_renameat2};
pub use link::{handle_link, handle_linkat, handle_symlink, handle_symlinkat, handle_readlinkat};
pub use perm::{handle_chmod, handle_fchmod, handle_fchmodat, handle_chown, handle_fchown, handle_lchown, handle_fchownat, handle_umask};
pub use open::{handle_mknod, handle_mknodat, handle_openat, handle_newfstatat};
pub use statfs::{handle_faccessat, handle_statfs, handle_fstatfs, handle_statx};
pub use mount::{handle_chroot, handle_mount, handle_umount2};
