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

pub use crt::{crt0_start, crti_fini, crti_init};
pub use errno::{errno, set_errno, Errno};
pub use locale::{localeconv, setlocale, LC_ALL, LC_CTYPE};
pub use pthread::{pthread_cond_init, pthread_cond_signal, pthread_cond_wait};
pub use pthread::{pthread_create, pthread_exit, pthread_join, pthread_self};
pub use pthread::{pthread_mutex_init, pthread_mutex_lock, pthread_mutex_unlock};
pub use signal::{kill, raise, sigaction, signal};
pub use stdio::{fclose, fopen, fprintf, fread, fwrite, printf, snprintf, sprintf};
pub use stdlib::{abort, calloc, exit, free, getenv, malloc, realloc, setenv};
pub use string::{memcmp, memcpy, memmove, memset, strcmp, strcpy, strlen, strncpy};
pub use time::{clock_gettime, gettimeofday, nanosleep, time};
pub use unistd::{_exit, close, execve, fork, getpid, getppid, read, write};

pub fn get_libc_start_main_addr() -> u64 {
    crt::crt0_start as *const () as usize as u64
}
pub fn get_exit_addr() -> u64 {
    stdlib::exit as *const () as usize as u64
}
pub fn get_write_addr() -> u64 {
    unistd::write as *const () as usize as u64
}
pub fn get_read_addr() -> u64 {
    unistd::read as *const () as usize as u64
}
pub fn get_open_addr() -> u64 {
    unistd::open as *const () as usize as u64
}
pub fn get_close_addr() -> u64 {
    unistd::close as *const () as usize as u64
}
pub fn get_malloc_addr() -> u64 {
    stdlib::malloc as *const () as usize as u64
}
pub fn get_free_addr() -> u64 {
    stdlib::free as *const () as usize as u64
}
pub fn get_mmap_addr() -> u64 {
    stdlib::mmap::mmap as *const () as usize as u64
}
pub fn get_munmap_addr() -> u64 {
    stdlib::mmap::munmap as *const () as usize as u64
}
pub fn get_brk_addr() -> u64 {
    stdlib::mmap::brk as *const () as usize as u64
}
pub fn get_getpid_addr() -> u64 {
    unistd::getpid as *const () as usize as u64
}
pub fn get_fork_addr() -> u64 {
    unistd::fork as *const () as usize as u64
}
pub fn get_execve_addr() -> u64 {
    unistd::execve as *const () as usize as u64
}
pub fn get_waitpid_addr() -> u64 {
    unistd::waitpid as *const () as usize as u64
}
pub fn get_ioctl_addr() -> u64 {
    unistd::ioctl as *const () as usize as u64
}
pub fn get_printf_addr() -> u64 {
    stdio::printf as *const () as usize as u64
}
pub fn get_puts_addr() -> u64 {
    stdio::fopen::puts as *const () as usize as u64
}
pub fn get_fopen_addr() -> u64 {
    stdio::fopen as *const () as usize as u64
}
pub fn get_fclose_addr() -> u64 {
    stdio::fclose as *const () as usize as u64
}
pub fn get_fread_addr() -> u64 {
    stdio::fread as *const () as usize as u64
}
pub fn get_fwrite_addr() -> u64 {
    stdio::fwrite as *const () as usize as u64
}
pub fn get_stack_chk_fail_addr() -> u64 {
    crt::crti::__stack_chk_fail as *const () as usize as u64
}
pub fn get_cxa_atexit_addr() -> u64 {
    crt::crti::__cxa_atexit as *const () as usize as u64
}
