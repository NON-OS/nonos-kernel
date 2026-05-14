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

mod errno;
mod header;
mod limits;
mod ops;

pub use errno::{
    E_BAD_LEN, E_BAD_MAGIC, E_BAD_OP, E_BAD_VERSION, E_NO_IP_LINK, E_NO_PORT, E_OK, E_PORT_IN_USE,
    E_RX_EMPTY,
};
pub use header::MAGIC;
pub use limits::{IPC_PAYLOAD_MAX, UDP_PAYLOAD_MAX};
pub use ops::{OP_BIND, OP_HEALTHCHECK, OP_RECV, OP_SEND, OP_UNBIND};
