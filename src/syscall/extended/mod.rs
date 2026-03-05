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
pub use eventfd::*;
pub use fd::*;
pub use filesystem::*;
pub use memory::*;
pub use misc::*;
pub use process::*;
pub use sync::*;
pub use time::*;

pub use inotify::{
    IN_CLOEXEC, IN_NONBLOCK,
    IN_ACCESS, IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE, IN_CLOSE_NOWRITE,
    IN_OPEN, IN_MOVED_FROM, IN_MOVED_TO, IN_CREATE, IN_DELETE,
    IN_DELETE_SELF, IN_MOVE_SELF, IN_CLOSE, IN_MOVE, IN_ALL_EVENTS,
    IN_ONLYDIR, IN_DONT_FOLLOW, IN_EXCL_UNLINK, IN_MASK_CREATE,
    IN_MASK_ADD, IN_ISDIR, IN_ONESHOT, IN_UNMOUNT, IN_Q_OVERFLOW, IN_IGNORED,
    InotifyEvent, InotifyStats,
    handle_inotify_init, handle_inotify_init1,
    handle_inotify_add_watch, handle_inotify_rm_watch,
    inotify_read, inotify_close, notify_event, notify_move,
    inotify_has_events, is_inotify, fd_to_inotify_id, get_inotify_stats,
};

pub use sched::{
    PRIO_PROCESS, PRIO_PGRP, PRIO_USER,
    handle_sched_setparam, handle_sched_getparam,
    handle_sched_setscheduler, handle_sched_getscheduler,
    handle_sched_get_priority_max, handle_sched_get_priority_min,
    handle_sched_rr_get_interval,
    handle_sched_setaffinity, handle_sched_getaffinity,
    handle_sched_setattr, handle_sched_getattr,
    handle_getpriority, handle_setpriority,
    handle_ioprio_set, handle_ioprio_get,
    handle_sched_yield,
};

pub use epoll::{
    EpollEvent, EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD,
    EPOLLIN, EPOLLPRI, EPOLLOUT, EPOLLRDNORM, EPOLLRDBAND, EPOLLWRNORM, EPOLLWRBAND,
    EPOLLMSG, EPOLLERR, EPOLLHUP, EPOLLRDHUP, EPOLLEXCLUSIVE, EPOLLWAKEUP,
    EPOLLONESHOT, EPOLLET,
    handle_epoll_create, handle_epoll_create1, handle_epoll_ctl,
    handle_epoll_wait, handle_epoll_pwait,
    is_epoll_fd, fd_to_epoll_id, close_epoll, check_fd_events_external,
};

pub use select::{
    FD_SETSIZE, POLLIN, POLLPRI, POLLOUT, POLLERR, POLLHUP, POLLNVAL,
    POLLRDNORM, POLLRDBAND, POLLWRNORM, POLLWRBAND, PollFd,
    handle_select, handle_pselect6, handle_ppoll, handle_poll,
};

pub use signalfd::{
    SFD_CLOEXEC, SFD_NONBLOCK, SIGNALFD_SIGINFO_SIZE,
    SignalfdSiginfo, SignalfdInfo, SignalfdStats,
    handle_signalfd, handle_signalfd4,
    signalfd_read, signalfd_close, route_signal_to_signalfd,
    get_signalfd_info, signalfd_has_pending, fd_to_signalfd_id,
    is_signalfd, signalfd_count, get_signalfd_stats, cleanup_process_signalfds,
};

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
