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
pub mod eventfd_ops;
pub mod eventfd_types;
pub mod fd;
pub mod filesystem;
pub mod inotify;
pub mod ipc;
pub mod memory;
pub mod misc;
pub mod process;
pub mod rlimit;
pub mod sched;
pub mod select;
pub mod signalfd;
pub mod sync;
pub mod sysinfo;
pub mod time;
pub mod timer;

pub use admin::*;
pub use eventfd_ops::{
    eventfd_close, eventfd_count, eventfd_is_readable, eventfd_is_writable, eventfd_read,
    eventfd_write, fd_to_eventfd_id, get_eventfd_info, get_eventfd_stats, handle_eventfd,
    handle_eventfd2, is_eventfd, EventFdInfo, EventFdStats,
};
pub use eventfd_types::{
    EventFdInstance, EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE, EVENTFD_INSTANCES, EVENTFD_MAX,
    FD_TO_EVENTFD, MAX_EVENTFD_INSTANCES, NEXT_EVENTFD_ID, NEXT_FD,
};
pub use fd::*;
pub use filesystem::*;
pub use memory::*;
pub use misc::*;
pub use process::*;
pub use rlimit::*;
pub use sync::*;
pub use sysinfo::*;
pub use time::*;

pub use inotify::{
    fd_to_inotify_id, get_inotify_stats, handle_inotify_add_watch, handle_inotify_init,
    handle_inotify_init1, handle_inotify_rm_watch, inotify_close, inotify_has_events, inotify_read,
    is_inotify, notify_event, notify_move, InotifyEvent, InotifyStats, IN_ACCESS, IN_ALL_EVENTS,
    IN_ATTRIB, IN_CLOEXEC, IN_CLOSE, IN_CLOSE_NOWRITE, IN_CLOSE_WRITE, IN_CREATE, IN_DELETE,
    IN_DELETE_SELF, IN_DONT_FOLLOW, IN_EXCL_UNLINK, IN_IGNORED, IN_ISDIR, IN_MASK_ADD,
    IN_MASK_CREATE, IN_MODIFY, IN_MOVE, IN_MOVED_FROM, IN_MOVED_TO, IN_MOVE_SELF, IN_NONBLOCK,
    IN_ONESHOT, IN_ONLYDIR, IN_OPEN, IN_Q_OVERFLOW, IN_UNMOUNT,
};

pub use sched::{
    handle_getpriority, handle_ioprio_get, handle_ioprio_set, handle_sched_get_priority_max,
    handle_sched_get_priority_min, handle_sched_getaffinity, handle_sched_getattr,
    handle_sched_getparam, handle_sched_getscheduler, handle_sched_rr_get_interval,
    handle_sched_setaffinity, handle_sched_setattr, handle_sched_setparam,
    handle_sched_setscheduler, handle_sched_yield, handle_setpriority, PRIO_PGRP, PRIO_PROCESS,
    PRIO_USER,
};

pub use epoll::{
    check_fd_events_external, close_epoll, fd_to_epoll_id, handle_epoll_create,
    handle_epoll_create1, handle_epoll_ctl, handle_epoll_pwait, handle_epoll_wait, is_epoll_fd,
    EpollEvent, EPOLLERR, EPOLLET, EPOLLEXCLUSIVE, EPOLLHUP, EPOLLIN, EPOLLMSG, EPOLLONESHOT,
    EPOLLOUT, EPOLLPRI, EPOLLRDBAND, EPOLLRDHUP, EPOLLRDNORM, EPOLLWAKEUP, EPOLLWRBAND,
    EPOLLWRNORM, EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD,
};

pub use select::{
    handle_poll, handle_ppoll, handle_pselect6, handle_select, PollFd, FD_SETSIZE, POLLERR,
    POLLHUP, POLLIN, POLLNVAL, POLLOUT, POLLPRI, POLLRDBAND, POLLRDNORM, POLLWRBAND, POLLWRNORM,
};

pub use signalfd::{
    cleanup_process_signalfds, fd_to_signalfd_id, get_signalfd_info, get_signalfd_stats,
    handle_signalfd, handle_signalfd4, is_signalfd, route_signal_to_signalfd, signalfd_close,
    signalfd_count, signalfd_has_pending, signalfd_read, SignalfdInfo, SignalfdSiginfo,
    SignalfdStats, SFD_CLOEXEC, SFD_NONBLOCK, SIGNALFD_SIGINFO_SIZE,
};

pub use ipc::{
    get_ipc_stats, handle_msgctl, handle_msgget, handle_msgrcv, handle_msgsnd, handle_semctl,
    handle_semget, handle_semop, handle_semtimedop, handle_shmat, handle_shmctl, handle_shmdt,
    handle_shmget, IpcStats,
};

pub use timer::{
    close_timerfd, fd_to_timerfd_id, get_clock_time, get_timerfd_info_for_poll, handle_alarm,
    handle_clock_getres, handle_clock_gettime, handle_clock_settime, handle_futimesat,
    handle_getitimer, handle_setitimer, handle_timer_create, handle_timer_delete,
    handle_timer_getoverrun, handle_timer_gettime, handle_timer_settime, handle_timerfd_create,
    handle_timerfd_gettime, handle_timerfd_settime, handle_utime, handle_utimensat, handle_utimes,
    is_timerfd, timer_tick, timerfd_read, Itimerspec, Itimerval, Sigevent, TimerFdPollInfo,
    Timespec, Timeval,
};

pub use crate::syscall::dispatch::util::errno;

pub use crate::syscall::splice::{
    handle_splice, handle_sync_file_range, handle_tee, handle_vmsplice,
};
