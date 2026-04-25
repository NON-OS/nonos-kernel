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

pub mod check;
pub mod close;
pub mod ctl;
pub mod fd;
pub mod instance;
pub mod stats;
pub mod syscalls;
pub mod types;
pub mod util;
pub mod wait;

pub use types::{
    EpollEvent, EPOLLERR, EPOLLET, EPOLLEXCLUSIVE, EPOLLHUP, EPOLLIN, EPOLLMSG, EPOLLONESHOT,
    EPOLLOUT, EPOLLPRI, EPOLLRDBAND, EPOLLRDHUP, EPOLLRDNORM, EPOLLWAKEUP, EPOLLWRBAND,
    EPOLLWRNORM, EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD,
};

pub use syscalls::{
    handle_epoll_create, handle_epoll_create1, handle_epoll_ctl, handle_epoll_pwait,
    handle_epoll_wait,
};

pub use util::{check_fd_events_external, close_epoll, fd_to_epoll_id, is_epoll_fd};

pub use close::{
    cleanup_stale, close_all, close_all_for_process, epoll_close, remove_fd_from_all_instances,
};
pub use ctl::{
    all_monitored_fds, epoll_add, epoll_ctl, epoll_del, epoll_mod, get_fd_events, is_fd_monitored,
    monitored_fd_count,
};
pub use fd::{
    allocate_fd, bind_fd_to_instance, create_instance_with_fd, fd_count, fd_to_instance_id,
    instance_count, release_fd,
};
pub use stats::{
    get_stats, instance_stats, memory_usage, total_fds, total_instances, total_monitored_fds,
    EpollStats, InstanceStats,
};
pub use wait::{
    can_read, count_ready_events, epoll_poll, epoll_wait_blocking, has_ready_events, peek_events,
};
