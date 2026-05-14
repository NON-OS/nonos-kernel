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

//! P0 op discriminants. Adding a new op needs both a userland
//! handler and a kernel client; nothing else routes by op.

pub const OP_HEALTHCHECK: u16 = 0x0001;
pub const OP_CONTROLLER_STATUS: u16 = 0x0002;
pub const OP_PORT_STATUS: u16 = 0x0003;
pub const OP_ENABLE_SLOT: u16 = 0x0004;
pub const OP_DISABLE_SLOT: u16 = 0x0005;
pub const OP_ADDRESS_DEVICE: u16 = 0x0006;
pub const OP_GET_DEVICE_DESCRIPTOR: u16 = 0x0007;
pub const OP_GET_CONFIG_DESCRIPTOR: u16 = 0x0008;
