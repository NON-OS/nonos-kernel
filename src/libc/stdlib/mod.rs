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

pub mod env;
pub mod exit;
pub mod free;
pub mod malloc;
pub mod mmap;

pub use env::{environ_ptr, getenv, putenv, setenv, unsetenv};
pub use exit::{_Exit, abort, atexit, atexit_register, exit, quick_exit};
pub use free::free;
pub use malloc::{aligned_alloc, calloc, malloc, posix_memalign, realloc};
pub use mmap::{brk, mmap, munmap, sbrk};
