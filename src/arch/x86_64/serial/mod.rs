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

pub mod buffer;
pub mod constants;
pub mod error;
pub mod interrupt;
pub mod ops;
pub mod state;
pub mod stats;
pub mod types;
pub mod writer;

pub use constants::{
    COM1_BASE, COM1_IRQ, COM2_BASE, COM2_IRQ, COM3_BASE, COM3_IRQ, COM4_BASE, COM4_IRQ,
    MAX_COM_PORTS, RX_BUFFER_SIZE, TX_TIMEOUT, UART_CLOCK,
};
pub use error::SerialError;
pub use types::{BaudRate, DataBits, Parity, SerialConfig, StopBits};
pub use state::{SerialStats, SerialStatsSnapshot};
pub use writer::SerialWriter;

pub use ops::{
    available, available_from_port, init, init_port, is_port_initialized,
    module_is_initialized as is_initialized, read_byte, read_byte_direct_from_port,
    read_byte_from_port, write_byte, write_byte_to_port, write_str, write_str_to_port,
};
pub use interrupt::{
    handle_com1_interrupt, handle_com2_interrupt, handle_com3_interrupt, handle_com4_interrupt,
    handle_interrupt,
};
pub use stats::{get_primary_stats, get_stats, reset_stats};
