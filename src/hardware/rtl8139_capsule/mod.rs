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

//! Kernel-side glue for the RTL8139 userland driver capsule. The
//! kernel embeds and spawns the signed capsule, then speaks a thin
//! frame/status IPC contract. PIO, IRQ, DMA, reset, RX, and TX stay
//! inside `driver.rtl8139_0`.

mod capability;
pub mod client;
mod embed;
mod error;
mod protocol;
mod spawn;
mod state;

pub use client::{
    healthcheck, link_status, mac_address, rx_packet, stats, tx_packet, Rtl8139Stats, RxPacket,
};
pub use error::DriverRtl8139Error;
pub use spawn::{spawn_driver_rtl8139_capsule, SpawnError};
pub use state::shared_state;
