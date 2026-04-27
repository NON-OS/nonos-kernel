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
use super::logs::Log;
use super::types::RpcResult;
use super::utils::{extract_json_hex_u64, extract_json_string};
use alloc::{string::String, vec::Vec};

#[derive(Debug, Clone)]
pub struct TransactionReceipt {
    pub transaction_hash: String,
    pub block_number: u64,
    pub block_hash: String,
    pub gas_used: u64,
    pub status: bool,
    pub contract_address: Option<String>,
    pub logs: Vec<Log>,
}

impl TransactionReceipt {
    pub(super) fn from_json(json: &str) -> RpcResult<Self> {
        Ok(Self {
            transaction_hash: extract_json_string(json, "transactionHash").unwrap_or_default(),
            block_number: extract_json_hex_u64(json, "blockNumber").unwrap_or(0),
            block_hash: extract_json_string(json, "blockHash").unwrap_or_default(),
            gas_used: extract_json_hex_u64(json, "gasUsed").unwrap_or(0),
            status: extract_json_hex_u64(json, "status").unwrap_or(0) == 1,
            contract_address: extract_json_string(json, "contractAddress"),
            logs: Vec::new(),
        })
    }
}
