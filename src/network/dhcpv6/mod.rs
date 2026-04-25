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

pub mod client;
pub mod duid;
pub mod message;
pub mod options;

pub use client::{get_dhcpv6_state, start_dhcpv6, Dhcpv6Client, Dhcpv6ClientState};
pub use duid::{generate_duid_ll, generate_duid_llt, Duid, DuidType};
pub use message::{build_dhcpv6, parse_dhcpv6, Dhcpv6Message, Dhcpv6MessageType};
pub use options::{build_options, parse_options, Dhcpv6Option, Dhcpv6OptionType};
