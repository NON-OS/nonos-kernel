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

mod descriptor;
mod dma;
mod ethernet;
mod mac;
mod packet;
mod types;

pub use descriptor::{validate_chain_length, validate_descriptor_index};
pub use dma::validate_dma_address;
pub use ethernet::{validate_ethernet_frame, validate_ethernet_frame_extended};
pub use mac::{validate_mac_address, validate_source_mac};
pub use packet::{validate_packet_size, validate_rx_packet, validate_tx_buffer};
pub use types::EtherType;
