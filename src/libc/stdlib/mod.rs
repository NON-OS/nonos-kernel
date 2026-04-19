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

pub mod malloc;
pub mod free;
pub mod exit;
pub mod env;
pub mod mmap;

pub use malloc::{malloc, calloc, realloc, aligned_alloc, posix_memalign};
pub use free::free;
pub use exit::{exit, abort, _Exit, atexit, atexit_register, quick_exit};
pub use env::{getenv, setenv, unsetenv, putenv, environ_ptr};
pub use mmap::{mmap, munmap, brk, sbrk};
