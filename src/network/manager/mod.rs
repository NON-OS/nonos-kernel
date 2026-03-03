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


mod init;
mod poll;
mod monitor;

pub use init::{init, init_with_preset, configure_ipv4};
pub use poll::{run_network_stack, poll_network, network_tick, get_poll_count};
pub use monitor::{get_suspicious_flows, read_flow_bytes, get_recent_dns_queries};
