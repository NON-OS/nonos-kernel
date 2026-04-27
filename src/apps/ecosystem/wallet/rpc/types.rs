// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use alloc::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcNetwork {
    Mainnet,
    Sepolia,
    Localhost,
}

impl RpcNetwork {
    pub fn chain_id(&self) -> u64 {
        match self {
            RpcNetwork::Mainnet => 1,
            RpcNetwork::Sepolia => 11155111,
            RpcNetwork::Localhost => 31337,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RpcEndpoint {
    pub url: String,
    pub network: RpcNetwork,
    pub priority: u8,
    pub healthy: bool,
}

impl RpcEndpoint {
    pub const fn mainnet_endpoints() -> [&'static str; 4] {
        ["ethereum.publicnode.com", "1rpc.io/eth", "eth.merkle.io", "rpc.ankr.com/eth"]
    }
    pub const fn sepolia_endpoints() -> [&'static str; 4] {
        [
            "ethereum-sepolia-rpc.publicnode.com",
            "rpc.sepolia.org",
            "1rpc.io/sepolia",
            "rpc.ankr.com/eth_sepolia",
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcError {
    NetworkError,
    ParseError,
    InvalidResponse,
    RateLimited,
    ServerError,
    InvalidParams,
    MethodNotFound,
    InternalError,
    ExecutionReverted,
    InsufficientFunds,
    NonceTooLow,
    GasTooLow,
    Timeout,
}

pub type RpcResult<T> = Result<T, RpcError>;
