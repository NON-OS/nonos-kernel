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

// IPv4 MTU 1500 - 20-byte IP header - 8-byte UDP header.
pub const UDP_PAYLOAD_MAX: usize = 1472;

// Add a small ceiling above payload for op-specific framing bytes
// (bind port, src/dst/dst_port body) so a single shared rx/tx
// scratch buffer covers every op.
pub const IPC_PAYLOAD_MAX: usize = UDP_PAYLOAD_MAX + 64;
