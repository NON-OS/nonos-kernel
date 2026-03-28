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

mod types;
mod client;
mod transaction;
mod receipt;
mod logs;
mod erc20;
mod utils;
mod network;

pub use types::{RpcNetwork, RpcError, RpcResult, RpcEndpoint};
pub use client::EthRpcClient;
pub use transaction::TransactionCall;
pub use receipt::TransactionReceipt;
pub use logs::{Log, LogFilter};
pub use erc20::{balance_of, allowance, encode_transfer, encode_approve};
pub use network::{set_network, get_network, network_name, format_wei_to_eth};
