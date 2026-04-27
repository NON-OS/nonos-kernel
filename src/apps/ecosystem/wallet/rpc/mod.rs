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

mod client;
mod erc20;
mod logs;
mod network;
mod receipt;
mod transaction;
mod types;
mod utils;

pub use client::EthRpcClient;
pub use erc20::{allowance, balance_of, encode_approve, encode_transfer};
pub use logs::{Log, LogFilter};
pub use network::{format_wei_to_eth, get_network, network_name, set_network};
pub use receipt::TransactionReceipt;
pub use transaction::TransactionCall;
pub use types::{RpcEndpoint, RpcError, RpcNetwork, RpcResult};
