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

use core::sync::atomic::Ordering;
use super::super::error::SerialError;
use super::super::state::{get_port, is_initialized, primary_port_index};
use super::io::{write_byte_timeout, read_byte_direct};

pub fn write_byte(byte: u8) -> Result<(), SerialError> {
    let port_index = primary_port_index();
    write_byte_to_port(port_index, byte)
}

pub fn write_byte_to_port(port_index: usize, byte: u8) -> Result<(), SerialError> {
    let state = get_port(port_index).ok_or(SerialError::InvalidPort)?;

    if !state.is_initialized() {
        return Err(SerialError::NotInitialized);
    }

    match write_byte_timeout(state.base, byte) {
        Ok(()) => {
            state.stats.bytes_sent.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        Err(e) => {
            state.stats.tx_timeouts.fetch_add(1, Ordering::Relaxed);
            Err(e)
        }
    }
}

pub fn write_str(s: &str) {
    let port_index = primary_port_index();
    let _ = write_str_to_port(port_index, s);
}

pub fn write_str_to_port(port_index: usize, s: &str) -> Result<(), SerialError> {
    for byte in s.bytes() {
        if byte == b'\n' {
            write_byte_to_port(port_index, b'\r')?;
        }
        write_byte_to_port(port_index, byte)?;
    }
    Ok(())
}

pub fn read_byte() -> Option<u8> {
    let port_index = primary_port_index();
    read_byte_from_port(port_index)
}

pub fn read_byte_from_port(port_index: usize) -> Option<u8> {
    let state = get_port(port_index)?;
    state.rx_buffer.pop()
}

pub fn available() -> usize {
    let port_index = primary_port_index();
    available_from_port(port_index)
}

pub fn available_from_port(port_index: usize) -> usize {
    get_port(port_index).map(|s| s.rx_buffer.available()).unwrap_or(0)
}

pub fn read_byte_direct_from_port(port_index: usize) -> Option<u8> {
    let state = get_port(port_index)?;

    if !state.is_initialized() {
        return None;
    }

    if let Some(byte) = read_byte_direct(state.base) {
        state.stats.bytes_received.fetch_add(1, Ordering::Relaxed);
        Some(byte)
    } else {
        None
    }
}

pub fn is_port_initialized(port_index: usize) -> bool {
    get_port(port_index).map(|s| s.is_initialized()).unwrap_or(false)
}

pub fn module_is_initialized() -> bool {
    is_initialized()
}
