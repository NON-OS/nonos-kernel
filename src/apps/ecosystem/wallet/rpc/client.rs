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
use super::logs::{Log, LogFilter};
use super::receipt::TransactionReceipt;
use super::transaction::TransactionCall;
use super::types::{RpcEndpoint, RpcError, RpcNetwork, RpcResult};
use super::utils::{
    bytes_to_hex, hex_to_bytes, parse_hex_u128, parse_hex_u64, parse_json_rpc_response,
    send_http_post,
};
use alloc::{format, string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

pub struct EthRpcClient {
    endpoints: Vec<RpcEndpoint>,
    current_idx: usize,
    timeout_ms: u32,
}

impl EthRpcClient {
    pub fn new(network: RpcNetwork) -> Self {
        let urls = match network {
            RpcNetwork::Mainnet => RpcEndpoint::mainnet_endpoints().to_vec(),
            RpcNetwork::Sepolia => RpcEndpoint::sepolia_endpoints().to_vec(),
            RpcNetwork::Localhost => alloc::vec!["127.0.0.1:8545"],
        };
        let endpoints = urls
            .iter()
            .enumerate()
            .map(|(i, url)| RpcEndpoint {
                url: String::from(*url),
                network,
                priority: i as u8,
                healthy: true,
            })
            .collect();
        Self { endpoints, current_idx: 0, timeout_ms: 30000 }
    }

    pub fn with_endpoint(url: &str, network: RpcNetwork) -> Self {
        Self {
            endpoints: alloc::vec![RpcEndpoint {
                url: String::from(url),
                network,
                priority: 0,
                healthy: true
            }],
            current_idx: 0,
            timeout_ms: 30000,
        }
    }

    fn next_id(&self) -> u64 {
        REQUEST_ID.fetch_add(1, Ordering::Relaxed)
    }
    fn current_endpoint(&self) -> &RpcEndpoint {
        &self.endpoints[self.current_idx]
    }
    fn build_request(&self, method: &str, params: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","method":"{}","params":{},"id":{}}}"#,
            method,
            params,
            self.next_id()
        )
    }
    fn rotate_endpoint(&mut self) {
        if self.endpoints.len() > 1 {
            self.current_idx = (self.current_idx + 1) % self.endpoints.len();
        }
    }

    pub fn get_balance(&mut self, address: &str) -> RpcResult<u128> {
        parse_hex_u128(&self.call("eth_getBalance", &format!(r#"["{}","latest"]"#, address))?)
    }
    pub fn get_transaction_count(&mut self, address: &str) -> RpcResult<u64> {
        parse_hex_u64(
            &self.call("eth_getTransactionCount", &format!(r#"["{}","pending"]"#, address))?,
        )
    }
    pub fn get_gas_price(&mut self) -> RpcResult<u128> {
        parse_hex_u128(&self.call("eth_gasPrice", "[]")?)
    }
    pub fn get_max_priority_fee(&mut self) -> RpcResult<u128> {
        parse_hex_u128(&self.call("eth_maxPriorityFeePerGas", "[]")?)
    }
    pub fn estimate_gas(&mut self, tx: &TransactionCall) -> RpcResult<u64> {
        parse_hex_u64(&self.call("eth_estimateGas", &format!(r#"[{}]"#, tx.to_json()))?)
    }
    pub fn send_raw_transaction(&mut self, signed_tx: &[u8]) -> RpcResult<String> {
        self.call("eth_sendRawTransaction", &format!(r#"["{}"]"#, bytes_to_hex(signed_tx)))
    }
    pub fn get_block_number(&mut self) -> RpcResult<u64> {
        parse_hex_u64(&self.call("eth_blockNumber", "[]")?)
    }
    pub fn get_chain_id(&mut self) -> RpcResult<u64> {
        parse_hex_u64(&self.call("eth_chainId", "[]")?)
    }

    pub fn get_transaction_receipt(
        &mut self,
        tx_hash: &str,
    ) -> RpcResult<Option<TransactionReceipt>> {
        let response = self.call("eth_getTransactionReceipt", &format!(r#"["{}"]"#, tx_hash))?;
        if response == "null" || response.is_empty() {
            return Ok(None);
        }
        TransactionReceipt::from_json(&response).map(Some)
    }

    pub fn eth_call(&mut self, tx: &TransactionCall, block: &str) -> RpcResult<Vec<u8>> {
        hex_to_bytes(&self.call("eth_call", &format!(r#"[{},"{}"]"#, tx.to_json(), block))?)
    }
    pub fn get_logs(&mut self, filter: &LogFilter) -> RpcResult<Vec<Log>> {
        Log::parse_array(&self.call("eth_getLogs", &format!(r#"[{}]"#, filter.to_json()))?)
    }

    pub(super) fn call(&mut self, method: &str, params: &str) -> RpcResult<String> {
        let max_retries = self.endpoints.len();
        let mut last_error = RpcError::NetworkError;
        for _ in 0..max_retries {
            let request = self.build_request(method, params);
            match send_http_post(&self.current_endpoint().url, &request, self.timeout_ms) {
                Ok(response) => return parse_json_rpc_response(&response),
                Err(e) => {
                    last_error = e;
                    self.rotate_endpoint();
                }
            }
        }
        Err(last_error)
    }
}
