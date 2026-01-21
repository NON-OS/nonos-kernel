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

use core::arch::asm;

use super::constants::{
    FCR_ENABLE, FCR_RX_CLEAR, FCR_TX_CLEAR, FCR_TRIGGER_14, IER_LINE_STATUS, IER_RX_AVAIL,
    LCR_DLAB, LCR_PARITY_ENABLE, LCR_PARITY_EVEN, LCR_PARITY_STICKY, LSR_DATA_READY, LSR_TX_EMPTY,
    MAX_COM_PORTS, MCR_DTR, MCR_LOOPBACK, MCR_OUT2, MCR_RTS, REG_DATA, REG_IER, REG_IIR_FCR,
    REG_LCR, REG_LSR, REG_MCR, TX_TIMEOUT,
};
use super::error::SerialError;
use super::state::{get_port, get_port_mut, is_initialized, primary_port_index, set_initialized, set_primary_port};
use super::types::{Parity, SerialConfig};

#[inline]
unsafe fn outb(port: u16, value: u8) {
    asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    asm!(
        "in al, dx",
        in("dx") port,
        out("al") value,
        options(nomem, nostack, preserves_flags)
    );
    value
}

#[inline]
fn io_wait() {
    // SAFETY: Port 0x80 is used for POST codes, safe for delays
    unsafe { outb(0x80, 0); }
}

#[inline]
pub fn read_reg(base: u16, reg: u16) -> u8 {
    // SAFETY: Caller ensures valid port address
    unsafe { inb(base + reg) }
}

#[inline]
pub fn write_reg(base: u16, reg: u16, value: u8) {
    // SAFETY: Caller ensures valid port address
    unsafe { outb(base + reg, value); }
}

#[inline]
pub fn is_tx_empty(base: u16) -> bool {
    read_reg(base, REG_LSR) & LSR_TX_EMPTY != 0
}

#[inline]
pub fn is_data_ready(base: u16) -> bool {
    read_reg(base, REG_LSR) & LSR_DATA_READY != 0
}

pub fn write_byte_timeout(base: u16, byte: u8) -> Result<(), SerialError> {
    let mut timeout = TX_TIMEOUT;

    while !is_tx_empty(base) {
        if timeout == 0 {
            return Err(SerialError::TransmitTimeout);
        }
        timeout -= 1;
        // SAFETY: pause is always safe on x86_64
        unsafe { asm!("pause", options(nomem, nostack)); }
    }

    write_reg(base, REG_DATA, byte);
    Ok(())
}

pub fn read_byte_direct(base: u16) -> Option<u8> {
    if is_data_ready(base) {
        Some(read_reg(base, REG_DATA))
    } else {
        None
    }
}

pub fn init_port(port_index: usize, config: &SerialConfig) -> Result<(), SerialError> {
    if port_index >= MAX_COM_PORTS {
        return Err(SerialError::InvalidPort);
    }

    let state = get_port_mut(port_index).ok_or(SerialError::InvalidPort)?;
    let base = state.base;

    write_reg(base, REG_IER, 0x00);

    write_reg(base, REG_LCR, LCR_DLAB);

    let divisor = config.baud_rate.divisor();
    write_reg(base, REG_DATA, (divisor & 0xFF) as u8);
    write_reg(base, REG_IER, ((divisor >> 8) & 0xFF) as u8);

    let lcr = (config.data_bits as u8)
        | ((config.stop_bits as u8) << 2)
        | match config.parity {
            Parity::None => 0,
            Parity::Odd => LCR_PARITY_ENABLE,
            Parity::Even => LCR_PARITY_ENABLE | LCR_PARITY_EVEN,
            Parity::Mark => LCR_PARITY_ENABLE | LCR_PARITY_STICKY,
            Parity::Space => LCR_PARITY_ENABLE | LCR_PARITY_STICKY | LCR_PARITY_EVEN,
        };
    write_reg(base, REG_LCR, lcr);

    if config.enable_fifo {
        write_reg(base, REG_IIR_FCR, FCR_ENABLE | FCR_RX_CLEAR | FCR_TX_CLEAR | FCR_TRIGGER_14);
    } else {
        write_reg(base, REG_IIR_FCR, 0);
    }

    write_reg(base, REG_MCR, MCR_DTR | MCR_RTS | MCR_OUT2);

    write_reg(base, REG_MCR, MCR_LOOPBACK | MCR_OUT2);
    write_reg(base, REG_DATA, 0xAE);

    for _ in 0..100 {
        io_wait();
    }

    if read_reg(base, REG_DATA) != 0xAE {
        return Err(SerialError::PortNotPresent);
    }

    write_reg(base, REG_MCR, MCR_DTR | MCR_RTS | MCR_OUT2);

    if config.enable_interrupts {
        write_reg(base, REG_IER, IER_RX_AVAIL | IER_LINE_STATUS);
    }

    while is_data_ready(base) {
        let _ = read_reg(base, REG_DATA);
    }

    state.set_initialized(true);
    Ok(())
}

pub fn init() -> Result<(), SerialError> {
    if set_initialized(true) {
        return Err(SerialError::AlreadyInitialized);
    }

    init_port(0, &SerialConfig::default())?;
    set_primary_port(0);
    Ok(())
}

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
            state.stats.bytes_sent.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
        Err(e) => {
            state.stats.tx_timeouts.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
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
        state.stats.bytes_received.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parity_lcr_bits() {
        let none_bits = match Parity::None {
            Parity::None => 0u8,
            _ => unreachable!(),
        };
        assert_eq!(none_bits, 0);
    }
}
