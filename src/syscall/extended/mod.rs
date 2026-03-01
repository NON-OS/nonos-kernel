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

pub mod admin;
pub mod epoll;
pub mod eventfd;
pub mod fd;
pub mod filesystem;
pub mod inotify;
pub mod ipc;
pub mod memory;
pub mod misc;
pub mod process;
pub mod sched;
pub mod select;
pub mod signalfd;
pub mod sync;
pub mod time;
pub mod timer;

pub use admin::*;
pub use epoll::*;
pub use eventfd::*;
pub use fd::*;
pub use filesystem::*;
pub use inotify::*;
pub use memory::*;
pub use misc::*;
pub use process::*;
pub use sched::*;
pub use select::*;
pub use signalfd::*;
pub use sync::*;
pub use time::*;

pub use ipc::{
    handle_shmget, handle_shmat, handle_shmdt, handle_shmctl,
    handle_semget, handle_semop, handle_semtimedop, handle_semctl,
    handle_msgget, handle_msgsnd, handle_msgrcv, handle_msgctl,
    IpcStats, get_ipc_stats,
};

pub use timer::{
    Timespec, Itimerspec, Itimerval, Timeval, Sigevent, TimerFdPollInfo,
    handle_clock_gettime, handle_clock_settime, handle_clock_getres, get_clock_time,
    handle_timer_create, handle_timer_settime, handle_timer_gettime, handle_timer_getoverrun, handle_timer_delete,
    handle_timerfd_create, handle_timerfd_settime, handle_timerfd_gettime, timerfd_read, get_timerfd_info_for_poll, is_timerfd, fd_to_timerfd_id, close_timerfd,
    handle_getitimer, handle_setitimer,
    handle_alarm,
    handle_utime, handle_utimes, handle_utimensat, handle_futimesat,
    timer_tick,
};

pub use crate::syscall::dispatch::util::errno;
