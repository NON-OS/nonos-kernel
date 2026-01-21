// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub fn syscall_socket(domain: u64, sock_type: u64, protocol: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::dispatch::network::handle_socket(domain, sock_type, protocol);
    result.value as u64
}

pub fn syscall_connect(fd: u64, addr: u64, addrlen: u64, flags: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::dispatch::network::handle_connect(fd, addr, addrlen, flags);
    result.value as u64
}

pub fn syscall_accept(fd: u64, addr: u64, addrlen: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::dispatch::network::handle_accept(fd, addr, addrlen);
    result.value as u64
}

pub fn syscall_bind(fd: u64, addr: u64, addrlen: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::dispatch::network::handle_bind(fd, addr, addrlen);
    result.value as u64
}

pub fn syscall_listen(fd: u64, backlog: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::dispatch::network::handle_listen(fd, backlog);
    result.value as u64
}

pub fn syscall_sendto(fd: u64, buf: u64, len: u64, flags: u64, _dest_addr: u64, _addrlen: u64) -> u64 {
    let result = crate::syscall::dispatch::network::handle_sendto(fd, buf, len, flags);
    result.value as u64
}

pub fn syscall_recvfrom(fd: u64, buf: u64, len: u64, flags: u64, _src_addr: u64, _addrlen: u64) -> u64 {
    let result = crate::syscall::dispatch::network::handle_recvfrom(fd, buf, len, flags);
    result.value as u64
}
