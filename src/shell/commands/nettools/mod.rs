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

//! Network tools shell commands.

pub mod dns;
pub mod helpers;
pub mod http;
pub mod ifconfig;
pub mod ip;
pub mod netstat;
pub mod ping;
pub mod traceroute;

pub use ifconfig::cmd_ifconfig;
pub use ip::{cmd_ip, cmd_route};
pub use ping::cmd_ping;
pub use dns::{cmd_dns, cmd_nslookup};
pub use netstat::{cmd_netstat, cmd_arp, cmd_ss};
pub use http::{cmd_wget, cmd_curl};
pub use traceroute::cmd_traceroute;
