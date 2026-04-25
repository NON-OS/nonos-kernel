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

mod dup;
mod fcntl;
mod io;
mod sync;
mod truncate;

pub use dup::{handle_dup, handle_dup2, handle_dup3, handle_pipe, handle_pipe2};
pub use fcntl::handle_fcntl;
pub use io::{
    handle_copy_file_range, handle_fadvise64, handle_pread64, handle_pwrite64, handle_readahead,
    handle_readv, handle_sendfile, handle_writev,
};
pub use sync::{
    handle_fallocate, handle_fdatasync, handle_flock, handle_fsync, handle_sync, handle_syncfs,
};
pub use truncate::{handle_creat, handle_ftruncate, handle_truncate};
