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

use alloc::format;
use alloc::string::String;

use crate::browser::net::mixnet::{self, Network};
use crate::browser::state::State;

/// The networks the settings page's Route row offers, left to right.
pub const NETWORKS: [Network; 3] = [Network::Nym, Network::Anyone, Network::Direct];

/// What the settings page says the next request leaves through. A manual
/// proxy only carries traffic on the direct network, so it is named there
/// and nowhere else.
pub fn network_line(state: &State) -> String {
    match (mixnet::chosen(), state.proxy.as_ref()) {
        (Network::Direct, Some(p)) => {
            format!("Network: direct, SOCKS5 proxy {}:{}", p.host, p.port)
        }
        (net, _) => format!("Network: {}", net.label()),
    }
}
