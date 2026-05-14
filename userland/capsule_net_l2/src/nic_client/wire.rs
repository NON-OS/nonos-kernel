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

//! virtio_net v1 envelope as the NIC capsule sees it. We talk to
//! the existing driver capsule unchanged: 20-byte v1 header, no
//! reply_port field. The reply comes back on the L2 capsule's
//! own pid inbox because we use `mk_ipc_call`, which loops the
//! send through `kernel_route_ipc` (sender pid = us) and
//! receives on endpoint 0.

pub const NIC_MAGIC: u32 = 0x4E4E_4554; // "NNET"
pub const NIC_VERSION: u16 = 1;
pub const NIC_HDR_LEN: usize = 20;

pub const OP_MAC_ADDRESS: u16 = 3;
pub const OP_TX_PACKET: u16 = 4;
pub const OP_RX_PACKET: u16 = 5;
