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

pub mod address;
pub mod dual_stack;
pub mod header;
pub mod icmpv6;
pub mod neighbor;
pub mod packet;
pub mod routing;
pub mod slaac;
pub mod socket;

pub use address::{format_ipv6, parse_ipv6, Ipv6Address, Ipv6Cidr, Ipv6Scope};
pub use dual_stack::{extract_ipv4, is_ipv4_mapped, map_ipv4_to_ipv6, DualStackSocket};
pub use header::{Ipv6ExtHeader, Ipv6Header, NextHeader};
pub use icmpv6::{handle_icmpv6, send_icmpv6, Icmpv6Message, Icmpv6Type};
pub use neighbor::{resolve_neighbor, NeighborCache, NeighborEntry, NeighborState};
pub use packet::{build_ipv6_packet, parse_ipv6_packet, Ipv6Packet};
pub use routing::{add_route, get_default_gateway, lookup_route, Ipv6Route, Ipv6RoutingTable};
pub use slaac::{generate_interface_id, perform_slaac, process_ra, SlaacState};
pub use socket::{bind_ipv6, create_ipv6_socket, Ipv6Socket, Ipv6SocketOptions};
