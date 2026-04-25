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

use super::network::{get_network, NetworkId};

pub(super) struct RpcEndpoint {
    pub host: &'static str,
    pub port: u16,
    pub fallback_ips: &'static [[u8; 4]],
}

pub(super) const MAINNET_ENDPOINTS: &[RpcEndpoint] = &[
    RpcEndpoint {
        host: "ethereum.publicnode.com",
        port: 443,
        fallback_ips: &[[65, 109, 115, 36], [65, 109, 115, 37]],
    },
    RpcEndpoint { host: "1rpc.io", port: 443, fallback_ips: &[[52, 77, 91, 106]] },
    RpcEndpoint { host: "eth.merkle.io", port: 443, fallback_ips: &[[104, 21, 64, 15]] },
];

pub(super) const SEPOLIA_ENDPOINTS: &[RpcEndpoint] = &[
    RpcEndpoint {
        host: "ethereum-sepolia-rpc.publicnode.com",
        port: 443,
        fallback_ips: &[[65, 109, 115, 38], [65, 109, 115, 39]],
    },
    RpcEndpoint { host: "rpc.sepolia.org", port: 443, fallback_ips: &[[65, 108, 79, 140]] },
    RpcEndpoint { host: "sepolia.drpc.org", port: 443, fallback_ips: &[[172, 67, 182, 156]] },
];

pub(super) fn get_endpoints() -> &'static [RpcEndpoint] {
    match get_network() {
        NetworkId::Mainnet => MAINNET_ENDPOINTS,
        NetworkId::Sepolia => SEPOLIA_ENDPOINTS,
    }
}
