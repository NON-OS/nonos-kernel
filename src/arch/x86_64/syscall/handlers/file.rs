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

use super::super::util::{is_pipe_read_fd, is_pipe_write_fd, pipe_fd_to_channel_id, scancode_to_ascii, convert_open_flags};

pub fn syscall_read(fd: u64, buf: u64, count: u64, _: u64, _: u64, _: u64) -> u64 {
    if buf == 0 || count == 0 {
        return (-14i64) as u64;
    }

    if is_pipe_read_fd(fd) {
        let channel_id = pipe_fd_to_channel_id(fd);
        let buffer = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count as usize) };
        match crate::ipc::recv_message(channel_id, buffer) {
            Ok(bytes) => bytes as u64,
            Err(crate::ipc::IpcError::WouldBlock) => (-11i64) as u64,
            Err(_) => (-9i64) as u64,
        }
    } else if is_pipe_write_fd(fd) {
        (-9i64) as u64
    } else {
        match fd {
            0 => {
                let buffer = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count as usize) };
                let mut bytes_read = 0usize;

                if let Some(input) = crate::arch::x86_64::keyboard::input::pop_event() {
                    use crate::arch::x86_64::keyboard::input::InputEventKind;
                    if let InputEventKind::KeyPress(key_event) = input.kind {
                        if let Some(ch) = scancode_to_ascii(key_event.scan_code) {
                            if bytes_read < count as usize {
                                buffer[bytes_read] = ch;
                                bytes_read += 1;
                            }
                        }
                    }
                }
                bytes_read as u64
            }
            1 | 2 => (-9i64) as u64,
            _ => {
                let buffer = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count as usize) };
                match crate::fs::nonos_vfs::vfs_read(fd as u32, buffer) {
                    Ok(bytes) => bytes as u64,
                    Err(_) => (-9i64) as u64,
                }
            }
        }
    }
}

pub fn syscall_write(fd: u64, buf: u64, count: u64, _: u64, _: u64, _: u64) -> u64 {
    if buf == 0 {
        return (-14i64) as u64;
    }
    if count == 0 {
        return 0;
    }

    let buffer = unsafe { core::slice::from_raw_parts(buf as *const u8, count as usize) };

    if is_pipe_write_fd(fd) {
        let channel_id = pipe_fd_to_channel_id(fd);
        match crate::ipc::send_message(channel_id, buffer) {
            Ok(()) => count,
            Err(crate::ipc::IpcError::BufferFull) => (-11i64) as u64,
            Err(crate::ipc::IpcError::PermissionDenied) => (-1i64) as u64,
            Err(_) => (-9i64) as u64,
        }
    } else if is_pipe_read_fd(fd) {
        (-9i64) as u64
    } else {
        match fd {
            0 => (-9i64) as u64,
            1 => {
                for &byte in buffer {
                    if byte.is_ascii() {
                        crate::arch::x86_64::vga::write_str(unsafe {
                            core::str::from_utf8_unchecked(&[byte])
                        });
                    }
                }
                count
            }
            2 => {
                crate::arch::x86_64::vga::set_color(
                    crate::arch::x86_64::vga::Color::LightRed,
                    crate::arch::x86_64::vga::Color::Black,
                );
                for &byte in buffer {
                    if byte.is_ascii() {
                        crate::arch::x86_64::vga::write_str(unsafe {
                            core::str::from_utf8_unchecked(&[byte])
                        });
                    }
                }
                crate::arch::x86_64::vga::set_color(
                    crate::arch::x86_64::vga::Color::LightGray,
                    crate::arch::x86_64::vga::Color::Black,
                );
                count
            }
            _ => {
                match crate::fs::nonos_vfs::vfs_write(fd as u32, buffer) {
                    Ok(bytes) => bytes as u64,
                    Err(_) => (-9i64) as u64,
                }
            }
        }
    }
}

pub fn syscall_open(pathname: u64, flags: u64, _mode: u64, _: u64, _: u64, _: u64) -> u64 {
    if pathname == 0 {
        return (-14i64) as u64;
    }

    let path_ptr = pathname as *const u8;
    let mut path_len = 0usize;
    const MAX_PATH: usize = 4096;

    unsafe {
        while path_len < MAX_PATH && *path_ptr.add(path_len) != 0 {
            path_len += 1;
        }
    }

    if path_len == 0 || path_len >= MAX_PATH {
        return (-36i64) as u64;
    }

    let path_slice = unsafe { core::slice::from_raw_parts(path_ptr, path_len) };
    let path_str = match core::str::from_utf8(path_slice) {
        Ok(s) => s,
        Err(_) => return (-22i64) as u64,
    };

    let vfs_flags = convert_open_flags(flags as u32);

    match crate::fs::nonos_vfs::vfs_open(path_str, vfs_flags) {
        Ok(fd) => fd as u64,
        Err(_) => (-2i64) as u64,
    }
}

pub fn syscall_close(fd: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    if fd < 3 {
        return (-9i64) as u64;
    }

    if is_pipe_read_fd(fd) || is_pipe_write_fd(fd) {
        let channel_id = pipe_fd_to_channel_id(fd);
        match crate::ipc::destroy_channel(channel_id) {
            Ok(()) => 0,
            Err(_) => (-9i64) as u64,
        }
    } else {
        match crate::fs::nonos_vfs::vfs_close(fd as u32) {
            Ok(()) => 0,
            Err(_) => (-9i64) as u64,
        }
    }
}

pub fn syscall_lseek(fd: u64, offset: u64, whence: u64, _: u64, _: u64, _: u64) -> u64 {
    match crate::fs::nonos_vfs::vfs_lseek(fd as u32, offset as i64, whence as u32) {
        Ok(pos) => pos as u64,
        Err(_) => (-9i64) as u64,
    }
}

pub fn syscall_pread64(fd: u64, buf: u64, count: u64, offset: u64, _: u64, _: u64) -> u64 {
    if buf == 0 || count == 0 {
        return (-14i64) as u64;
    }

    match crate::fs::fd::fd_read_at(fd as i32, buf as *mut u8, count as usize, offset as usize) {
        Ok(bytes) => bytes as u64,
        Err(e) => e.to_errno() as u64,
    }
}

pub fn syscall_pwrite64(fd: u64, buf: u64, count: u64, offset: u64, _: u64, _: u64) -> u64 {
    if buf == 0 || count == 0 {
        return (-14i64) as u64;
    }

    let current_pos = match crate::fs::fd::fd_lseek(fd as i32, 0, 1) {
        Ok(pos) => pos,
        Err(e) => return e.to_errno() as u64,
    };

    if let Err(e) = crate::fs::fd::fd_lseek(fd as i32, offset as i64, 0) {
        return e.to_errno() as u64;
    }

    let result = crate::fs::fd::fd_write(fd as i32, buf as *const u8, count as usize);
    let _ = crate::fs::fd::fd_lseek(fd as i32, current_pos, 0);

    match result {
        Ok(bytes) => bytes as u64,
        Err(e) => e.to_errno() as u64,
    }
}

pub fn syscall_stat(pathname: u64, statbuf: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    if pathname == 0 || statbuf == 0 {
        return (-14i64) as u64;
    }

    let stat_ptr = statbuf as *mut u8;
    unsafe {
        core::ptr::write_bytes(stat_ptr, 0, 144);
    }
    0
}

pub fn syscall_fstat(fd: u64, statbuf: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    if statbuf == 0 {
        return (-14i64) as u64;
    }

    match crate::fs::fd::fd_fstat(fd as i32, statbuf as *mut u8) {
        Ok(()) => 0,
        Err(e) => e.to_errno() as u64,
    }
}

pub fn syscall_lstat(pathname: u64, statbuf: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    syscall_stat(pathname, statbuf, 0, 0, 0, 0)
}

pub fn syscall_dup(fd: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    match crate::fs::fd::fd_dup(fd as i32) {
        Ok(new_fd) => new_fd as u64,
        Err(e) => e.to_errno() as u64,
    }
}

pub fn syscall_dup2(oldfd: u64, newfd: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    match crate::fs::fd::fd_dup2(oldfd as i32, newfd as i32) {
        Ok(fd) => fd as u64,
        Err(e) => e.to_errno() as u64,
    }
}

pub fn syscall_pipe(pipefd: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    if pipefd == 0 {
        return (-14i64) as u64;
    }

    match crate::ipc::create_channel(0) {
        Ok(channel_id) => {
            let fds = pipefd as *mut [i32; 2];
            unsafe {
                let read_fd = (channel_id | super::super::util::PIPE_READ_FLAG) as i32;
                let write_fd = (channel_id | super::super::util::PIPE_WRITE_FLAG) as i32;
                (*fds)[0] = read_fd;
                (*fds)[1] = write_fd;
            }
            0
        }
        Err(_) => (-24i64) as u64,
    }
}

pub fn syscall_ioctl(fd: u64, request: u64, arg: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::misc::handle_ioctl(fd as i32, request, arg);
    result.value as u64
}
