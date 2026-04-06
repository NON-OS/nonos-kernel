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
pub mod header;
pub mod packet;
pub mod routing;
pub mod neighbor;
pub mod icmpv6;
pub mod socket;
pub mod dual_stack;
pub mod slaac;

pub use address::{Ipv6Address, Ipv6Cidr, Ipv6Scope, parse_ipv6, format_ipv6};
pub use header::{Ipv6Header, Ipv6ExtHeader, NextHeader};
pub use packet::{Ipv6Packet, build_ipv6_packet, parse_ipv6_packet};
pub use routing::{Ipv6Route, Ipv6RoutingTable, add_route, lookup_route, get_default_gateway};
pub use neighbor::{NeighborEntry, NeighborCache, NeighborState, resolve_neighbor};
pub use icmpv6::{Icmpv6Type, Icmpv6Message, send_icmpv6, handle_icmpv6};
pub use socket::{Ipv6Socket, Ipv6SocketOptions, create_ipv6_socket, bind_ipv6};
pub use dual_stack::{DualStackSocket, is_ipv4_mapped, map_ipv4_to_ipv6, extract_ipv4};
pub use slaac::{SlaacState, generate_interface_id, perform_slaac, process_ra};
