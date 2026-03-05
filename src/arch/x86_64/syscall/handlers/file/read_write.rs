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

use super::super::super::util::{is_pipe_read_fd, is_pipe_write_fd, pipe_fd_to_channel_id, scancode_to_ascii};

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
