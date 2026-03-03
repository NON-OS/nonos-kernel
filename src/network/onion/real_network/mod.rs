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

mod connection;
mod limiter;
mod manager_connect;
mod manager_core;
mod manager_io;
mod pool;
mod types;

pub use connection::AnyoneConnection;
pub use manager_core::{anyone_network, get_anyone_network, init_anyone_network, AnyoneNetworkManager};
pub use types::{ConnectionState, ConnectionStats, DialOptions, NetworkStats, TlsConnectionState, TlsProvider, TlsSessionInfo};
