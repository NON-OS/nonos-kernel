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
    EpollEvent, EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD,
    EPOLLIN, EPOLLPRI, EPOLLOUT, EPOLLRDNORM, EPOLLRDBAND, EPOLLWRNORM, EPOLLWRBAND,
    EPOLLMSG, EPOLLERR, EPOLLHUP, EPOLLRDHUP, EPOLLEXCLUSIVE, EPOLLWAKEUP,
    EPOLLONESHOT, EPOLLET,
};

pub use syscalls::{
    handle_epoll_create, handle_epoll_create1, handle_epoll_ctl,
    handle_epoll_wait, handle_epoll_pwait,
};

pub use util::{is_epoll_fd, fd_to_epoll_id, close_epoll, check_fd_events_external};

pub use close::{epoll_close, close_all_for_process, cleanup_stale, close_all, remove_fd_from_all_instances};
pub use ctl::{epoll_add, epoll_mod, epoll_del, epoll_ctl, is_fd_monitored, get_fd_events, monitored_fd_count, all_monitored_fds};
pub use fd::{allocate_fd, release_fd, fd_to_instance_id, bind_fd_to_instance, fd_count, instance_count, create_instance_with_fd};
pub use stats::{get_stats, instance_stats, total_instances, total_fds, total_monitored_fds, memory_usage, EpollStats, InstanceStats};
pub use wait::{epoll_poll, epoll_wait_blocking, has_ready_events, count_ready_events, peek_events, can_read};
