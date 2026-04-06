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
