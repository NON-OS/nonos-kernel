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

pub mod create;
pub mod dir;
pub mod helpers;
pub mod link;
pub mod mount;
pub mod open;
pub mod path;
pub mod perm;
pub mod stat;
pub mod statfs;

pub use create::{handle_mkdirat, handle_renameat, handle_renameat2, handle_unlinkat};
pub use dir::{handle_fchdir, handle_getdents, handle_getdents64};
pub use helpers::{read_user_string, resolve_path_at};
pub use link::{handle_link, handle_linkat, handle_readlinkat, handle_symlink, handle_symlinkat};
pub use mount::{handle_chroot, handle_mount, handle_umount2};
pub use open::{handle_mknod, handle_mknodat, handle_newfstatat, handle_openat};
pub use path::{handle_chdir, handle_getcwd};
pub use perm::{
    handle_chmod, handle_chown, handle_fchmod, handle_fchmodat, handle_fchown, handle_fchownat,
    handle_lchown, handle_umask,
};
pub use stat::{handle_access, handle_lstat, handle_readlink};
pub use statfs::{handle_faccessat, handle_fstatfs, handle_statfs, handle_statx};
