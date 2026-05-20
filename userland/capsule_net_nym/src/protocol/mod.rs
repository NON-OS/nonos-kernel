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

mod endpoint;
mod errno;
mod header;
mod limits;
mod ops;

pub use endpoint::{REPLY_INBOX, REPLY_PORT, SERVICE_NAME, SERVICE_PORT};
pub use errno::{
    E_BAD_LEN, E_BAD_MAGIC, E_BAD_OP, E_BAD_VERSION, E_CRYPTO, E_NO_GATEWAY, E_NO_SESSION,
    E_NO_UDP, E_OK, E_RX_EMPTY, E_TABLE_FULL,
};
pub use header::MAGIC;
pub use limits::{COVER_BYTES, IPC_PAYLOAD_MAX, MIX_PAYLOAD_MAX, WIRE_PACKET_MAX};
pub use ops::{
    OP_CLOSE, OP_COVER_TICK, OP_HEALTHCHECK, OP_OPEN_SESSION, OP_RECV, OP_SEND, OP_SET_GATEWAY,
};
