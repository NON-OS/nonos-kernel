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

use super::types::*;
use super::instance::EPOLL_INSTANCES;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FdType {
    Socket,
    Pipe,
    File,
    EventFd,
    TimerFd,
    SignalFd,
    Epoll,
    Unknown,
}

pub struct FdInfo {
    pub fd_type: FdType,
    pub internal_id: usize,
    pub is_read_end: bool,
}

struct SocketEvents {
    readable: bool,
    writable: bool,
    error: bool,
    hangup: bool,
    peer_closed: bool,
}

struct PipeEvents {
    readable: bool,
    writable: bool,
    broken: bool,
}

struct EventFdEvents {
    readable: bool,
    writable: bool,
}

struct TimerFdEvents {
    expired: bool,
}

struct SignalFdEvents {
    pending: bool,
}

pub fn get_fd_info(fd: i32) -> Option<FdInfo> {
    use crate::process::fd_table;

    let fd_entry = fd_table::get_fd(fd as u32)?;

    let fd_type = match fd_entry.fd_type {
        fd_table::FdType::Socket => FdType::Socket,
        fd_table::FdType::Pipe => FdType::Pipe,
        fd_table::FdType::File => FdType::File,
        fd_table::FdType::EventFd => FdType::EventFd,
        fd_table::FdType::TimerFd => FdType::TimerFd,
        fd_table::FdType::SignalFd => FdType::SignalFd,
        fd_table::FdType::Epoll => FdType::Epoll,
        _ => FdType::Unknown,
    };

    Some(FdInfo {
        fd_type,
        internal_id: fd_entry.internal_id,
        is_read_end: fd_entry.is_read_end,
    })
}

fn check_socket_events(socket_id: usize) -> Option<SocketEvents> {
    if let Some(sock_info) = crate::network::stack::get_socket_info(socket_id as u32) {
        Some(SocketEvents {
            readable: sock_info.rx_available > 0 || sock_info.can_recv,
            writable: sock_info.tx_available > 0 || sock_info.can_send,
            error: sock_info.has_error,
            hangup: sock_info.is_closed,
            peer_closed: sock_info.peer_closed,
        })
    } else {
        None
    }
}

fn check_pipe_events(pipe_id: usize, is_read_end: bool) -> Option<PipeEvents> {
    if let Some(pipe_info) = crate::ipc::pipe::get_pipe_info(pipe_id) {
        Some(PipeEvents {
            readable: is_read_end && pipe_info.bytes_available > 0,
            writable: !is_read_end && pipe_info.space_available > 0,
            broken: pipe_info.is_broken,
        })
    } else {
        None
    }
}

fn check_eventfd_events(efd_id: usize) -> Option<EventFdEvents> {
    if let Some(efd_info) = crate::syscall::extended::eventfd::get_eventfd_info(efd_id) {
        Some(EventFdEvents {
            readable: efd_info.counter > 0,
            writable: efd_info.counter < (u64::MAX - 1),
        })
    } else {
        None
    }
}

fn check_timerfd_events(tfd_id: usize) -> Option<TimerFdEvents> {
    if let Some(tfd_info) = crate::syscall::extended::timer::get_timerfd_info_for_poll(tfd_id as u32) {
        Some(TimerFdEvents {
            expired: tfd_info.expirations > 0,
        })
    } else {
        None
    }
}

fn check_signalfd_events(sfd_id: usize) -> Option<SignalFdEvents> {
    if let Some(sfd_info) = crate::syscall::extended::signalfd::get_signalfd_info(sfd_id) {
        Some(SignalFdEvents {
            pending: sfd_info.pending_count > 0,
        })
    } else {
        None
    }
}

pub fn check_fd_events(fd: i32, interest: u32) -> u32 {
    let fd_info = match get_fd_info(fd) {
        Some(info) => info,
        None => return EPOLLERR | EPOLLHUP,
    };

    let mut ready = 0u32;

    match fd_info.fd_type {
        FdType::Socket => {
            if let Some(socket_events) = check_socket_events(fd_info.internal_id) {
                if (interest & EPOLLIN) != 0 && socket_events.readable {
                    ready |= EPOLLIN;
                }
                if (interest & EPOLLOUT) != 0 && socket_events.writable {
                    ready |= EPOLLOUT;
                }
                if socket_events.error {
                    ready |= EPOLLERR;
                }
                if socket_events.hangup {
                    ready |= EPOLLHUP;
                }
                if socket_events.peer_closed {
                    ready |= EPOLLRDHUP;
                }
            }
        }
        FdType::Pipe => {
            if let Some(pipe_events) = check_pipe_events(fd_info.internal_id, fd_info.is_read_end) {
                if (interest & EPOLLIN) != 0 && pipe_events.readable {
                    ready |= EPOLLIN;
                }
                if (interest & EPOLLOUT) != 0 && pipe_events.writable {
                    ready |= EPOLLOUT;
                }
                if pipe_events.broken {
                    ready |= EPOLLHUP;
                }
            }
        }
        FdType::File => {
            if (interest & EPOLLIN) != 0 {
                ready |= EPOLLIN;
            }
            if (interest & EPOLLOUT) != 0 {
                ready |= EPOLLOUT;
            }
        }
        FdType::EventFd => {
            if let Some(efd_events) = check_eventfd_events(fd_info.internal_id) {
                if (interest & EPOLLIN) != 0 && efd_events.readable {
                    ready |= EPOLLIN;
                }
                if (interest & EPOLLOUT) != 0 && efd_events.writable {
                    ready |= EPOLLOUT;
                }
            }
        }
        FdType::TimerFd => {
            if let Some(tfd_events) = check_timerfd_events(fd_info.internal_id) {
                if (interest & EPOLLIN) != 0 && tfd_events.expired {
                    ready |= EPOLLIN;
                }
            }
        }
        FdType::SignalFd => {
            if let Some(sfd_events) = check_signalfd_events(fd_info.internal_id) {
                if (interest & EPOLLIN) != 0 && sfd_events.pending {
                    ready |= EPOLLIN;
                }
            }
        }
        FdType::Epoll => {
            if (interest & EPOLLIN) != 0 {
                if let Some(instance) = EPOLL_INSTANCES.lock().get(&(fd_info.internal_id as u32)) {
                    if !instance.ready_events.is_empty() {
                        ready |= EPOLLIN;
                    }
                }
            }
        }
        FdType::Unknown => {
            ready |= EPOLLERR;
        }
    }

    ready
}
