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

mod api;
pub mod buffer;
pub mod constants;
pub mod device;
mod device_init;
mod device_interrupts;
mod device_mac_filter;
mod device_rx;
mod device_tx;
pub mod dma;
pub mod error;
pub mod header;
pub mod interface;
pub mod modern_regs;
pub mod rate_limiter;
pub mod stats;
pub mod validation;
pub mod virtqueue;

#[cfg(test)]
mod tests;

pub use api::{
    get_isr_handler, get_virtio_net_device, init_virtio_net, is_ready, mac_address, receive,
    statistics, super_virtio_isr, transmit, VIRTIO_NET,
};
pub use buffer::PacketBuffer;
pub use constants::*;
pub use device::VirtioNetDevice;
pub use error::VirtioNetError;
pub use header::VirtioNetHeader;
pub use interface::{VirtioNetInterface, VirtioSmolBridge, VIRTIO_SMOL_BRIDGE};
pub use rate_limiter::{RateLimiter, RateLimiterStats};
pub use stats::{NetworkStats, NetworkStatsSnapshot};
pub use validation::EtherType;
pub use virtqueue::{VirtQueue, VirtqDesc, VirtqUsedElem};
