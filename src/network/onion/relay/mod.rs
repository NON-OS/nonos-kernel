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


mod types;
mod connection;
mod manager;

pub use types::{
    OnionRelay, RelayConfig, RelayStatus, RelayMode, LinkId,
    ExitPolicy, ExitPolicyRule,
    CONNECT_TIMEOUT_MS, TLS_HANDSHAKE_TIMEOUT_MS, IO_READ_TIMEOUT_MS, IO_WRITE_TIMEOUT_MS,
    DEFAULT_OR_PORT, DEFAULT_DIR_PORT, DEFAULT_SOCKS_PORT, DEFAULT_BANDWIDTH_RATE,
};
pub use connection::{ORConnection, wrap_tls_app_record};
pub use manager::{RelayManager, RelayStats, BandwidthLimiter};
