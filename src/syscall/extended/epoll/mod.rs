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
pub mod instance;
pub mod syscalls;
pub mod types;
pub mod util;

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
