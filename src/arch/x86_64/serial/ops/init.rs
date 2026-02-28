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

use super::super::constants::{
    FCR_ENABLE, FCR_RX_CLEAR, FCR_TX_CLEAR, FCR_TRIGGER_14, IER_LINE_STATUS, IER_RX_AVAIL,
    LCR_DLAB, LCR_PARITY_ENABLE, LCR_PARITY_EVEN, LCR_PARITY_STICKY,
    MAX_COM_PORTS, MCR_DTR, MCR_LOOPBACK, MCR_OUT2, MCR_RTS, REG_DATA, REG_IER, REG_IIR_FCR,
    REG_LCR, REG_MCR,
};
use super::super::error::SerialError;
use super::super::state::{get_port_mut, set_initialized, set_primary_port};
use super::super::types::{Parity, SerialConfig};
use super::io::{io_wait, read_reg, write_reg, is_data_ready};

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
