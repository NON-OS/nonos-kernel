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

mod socket;
mod address;
mod stream;
mod dgram;
mod seqpacket;
mod ancillary;
mod listen;
mod syscall;

pub use socket::{UnixSocket, UnixSocketType};
pub use address::{SockaddrUn, parse_unix_address, format_unix_address};
pub use stream::{UnixStream, stream_connect, stream_accept};
pub use dgram::{UnixDgram, dgram_send, dgram_recv};
pub use seqpacket::{UnixSeqpacket, seqpacket_connect, seqpacket_accept};
pub use ancillary::{AncillaryData, ScmRights, ScmCredentials, parse_ancillary, build_ancillary};
pub use listen::{UnixListener, bind_unix, listen_unix};
pub use syscall::{unix_socket, unix_bind, unix_listen, unix_accept, unix_connect};
