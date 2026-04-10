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

pub mod crt;
pub mod errno;
pub mod locale;
pub mod pthread;
pub mod signal;
pub mod stdio;
pub mod stdlib;
pub mod string;
pub mod time;
pub mod unistd;

pub use crt::{crt0_start, crti_init, crti_fini};
pub use errno::{errno, set_errno, Errno};
pub use locale::{setlocale, localeconv, LC_ALL, LC_CTYPE};
pub use pthread::{pthread_create, pthread_join, pthread_exit, pthread_self};
pub use pthread::{pthread_mutex_init, pthread_mutex_lock, pthread_mutex_unlock};
pub use pthread::{pthread_cond_init, pthread_cond_wait, pthread_cond_signal};
pub use signal::{signal, sigaction, raise, kill};
pub use stdio::{printf, fprintf, sprintf, snprintf, fopen, fclose, fread, fwrite};
pub use stdlib::{malloc, free, calloc, realloc, exit, abort, getenv, setenv};
pub use string::{memcpy, memset, memmove, memcmp, strlen, strcmp, strcpy, strncpy};
pub use time::{time, clock_gettime, gettimeofday, nanosleep};
pub use unistd::{read, write, close, fork, execve, _exit, getpid, getppid};

pub fn get_libc_start_main_addr() -> u64 { crt::crt0_start as *const () as usize as u64 }
pub fn get_exit_addr() -> u64 { stdlib::exit as *const () as usize as u64 }
pub fn get_write_addr() -> u64 { unistd::write as *const () as usize as u64 }
pub fn get_read_addr() -> u64 { unistd::read as *const () as usize as u64 }
pub fn get_open_addr() -> u64 { 0 }
pub fn get_close_addr() -> u64 { unistd::close as *const () as usize as u64 }
pub fn get_malloc_addr() -> u64 { stdlib::malloc as *const () as usize as u64 }
pub fn get_free_addr() -> u64 { stdlib::free as *const () as usize as u64 }
pub fn get_mmap_addr() -> u64 { 0 }
pub fn get_munmap_addr() -> u64 { 0 }
pub fn get_brk_addr() -> u64 { 0 }
pub fn get_getpid_addr() -> u64 { unistd::getpid as *const () as usize as u64 }
pub fn get_fork_addr() -> u64 { unistd::fork as *const () as usize as u64 }
pub fn get_execve_addr() -> u64 { unistd::execve as *const () as usize as u64 }
pub fn get_waitpid_addr() -> u64 { 0 }
pub fn get_ioctl_addr() -> u64 { 0 }
pub fn get_printf_addr() -> u64 { stdio::printf as *const () as usize as u64 }
pub fn get_puts_addr() -> u64 { 0 }
pub fn get_fopen_addr() -> u64 { stdio::fopen as *const () as usize as u64 }
pub fn get_fclose_addr() -> u64 { stdio::fclose as *const () as usize as u64 }
pub fn get_fread_addr() -> u64 { stdio::fread as *const () as usize as u64 }
pub fn get_fwrite_addr() -> u64 { stdio::fwrite as *const () as usize as u64 }
pub fn get_stack_chk_fail_addr() -> u64 { 0 }
pub fn get_cxa_atexit_addr() -> u64 { 0 }
