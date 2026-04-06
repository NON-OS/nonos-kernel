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
pub mod message;
pub mod options;
pub mod duid;

pub use client::{Dhcpv6Client, Dhcpv6ClientState, start_dhcpv6, get_dhcpv6_state};
pub use message::{Dhcpv6Message, Dhcpv6MessageType, parse_dhcpv6, build_dhcpv6};
pub use options::{Dhcpv6Option, Dhcpv6OptionType, parse_options, build_options};
pub use duid::{Duid, DuidType, generate_duid_llt, generate_duid_ll};
