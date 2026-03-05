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

//! Ethereum JSON-RPC client.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::RwLock;

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
        [
            "ethereum.publicnode.com",
            "1rpc.io/eth",
            "eth.merkle.io",
            "rpc.ankr.com/eth",
        ]
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

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);
static CURRENT_NETWORK: RwLock<RpcNetwork> = RwLock::new(RpcNetwork::Sepolia);

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

        Self {
            endpoints,
            current_idx: 0,
            timeout_ms: 30000,
        }
    }

    pub fn with_endpoint(url: &str, network: RpcNetwork) -> Self {
        Self {
            endpoints: alloc::vec![RpcEndpoint {
                url: String::from(url),
                network,
                priority: 0,
                healthy: true,
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
            method, params, self.next_id()
        )
    }

    fn rotate_endpoint(&mut self) {
        if self.endpoints.len() > 1 {
            self.current_idx = (self.current_idx + 1) % self.endpoints.len();
        }
    }

    pub fn get_balance(&mut self, address: &str) -> RpcResult<u128> {
        let params = format!(r#"["{}","latest"]"#, address);
        let response = self.call("eth_getBalance", &params)?;
        parse_hex_u128(&response)
    }

    pub fn get_transaction_count(&mut self, address: &str) -> RpcResult<u64> {
        let params = format!(r#"["{}","pending"]"#, address);
        let response = self.call("eth_getTransactionCount", &params)?;
        parse_hex_u64(&response)
    }

    pub fn get_gas_price(&mut self) -> RpcResult<u128> {
        let response = self.call("eth_gasPrice", "[]")?;
        parse_hex_u128(&response)
    }

    pub fn get_max_priority_fee(&mut self) -> RpcResult<u128> {
        let response = self.call("eth_maxPriorityFeePerGas", "[]")?;
        parse_hex_u128(&response)
    }

    pub fn estimate_gas(&mut self, tx: &TransactionCall) -> RpcResult<u64> {
        let params = format!(r#"[{}]"#, tx.to_json());
        let response = self.call("eth_estimateGas", &params)?;
        parse_hex_u64(&response)
    }

    pub fn send_raw_transaction(&mut self, signed_tx: &[u8]) -> RpcResult<String> {
        let hex_tx = bytes_to_hex(signed_tx);
        let params = format!(r#"["{}"]"#, hex_tx);
        self.call("eth_sendRawTransaction", &params)
    }

    pub fn get_transaction_receipt(&mut self, tx_hash: &str) -> RpcResult<Option<TransactionReceipt>> {
        let params = format!(r#"["{}"]"#, tx_hash);
        let response = self.call("eth_getTransactionReceipt", &params)?;

        if response == "null" || response.is_empty() {
            return Ok(None);
        }

        TransactionReceipt::from_json(&response).map(Some)
    }

    pub fn eth_call(&mut self, tx: &TransactionCall, block: &str) -> RpcResult<Vec<u8>> {
        let params = format!(r#"[{},"{}"]"#, tx.to_json(), block);
        let response = self.call("eth_call", &params)?;
        hex_to_bytes(&response)
    }

    pub fn get_block_number(&mut self) -> RpcResult<u64> {
        let response = self.call("eth_blockNumber", "[]")?;
        parse_hex_u64(&response)
    }

    pub fn get_chain_id(&mut self) -> RpcResult<u64> {
        let response = self.call("eth_chainId", "[]")?;
        parse_hex_u64(&response)
    }

    pub fn get_logs(&mut self, filter: &LogFilter) -> RpcResult<Vec<Log>> {
        let params = format!(r#"[{}]"#, filter.to_json());
        let response = self.call("eth_getLogs", &params)?;
        Log::parse_array(&response)
    }

    fn call(&mut self, method: &str, params: &str) -> RpcResult<String> {
        let max_retries = self.endpoints.len();
        let mut last_error = RpcError::NetworkError;

        for _ in 0..max_retries {
            let request = self.build_request(method, params);
            let endpoint = self.current_endpoint();

            match send_http_post(&endpoint.url, &request, self.timeout_ms) {
                Ok(response) => {
                    return parse_json_rpc_response(&response);
                }
                Err(e) => {
                    last_error = e;
                    self.rotate_endpoint();
                }
            }
        }

        Err(last_error)
    }
}

#[derive(Debug, Clone)]
pub struct TransactionCall {
    pub from: Option<String>,
    pub to: String,
    pub gas: Option<u64>,
    pub gas_price: Option<u128>,
    pub value: Option<u128>,
    pub data: Option<Vec<u8>>,
}

impl TransactionCall {
    pub fn new(to: &str) -> Self {
        Self {
            from: None,
            to: String::from(to),
            gas: None,
            gas_price: None,
            value: None,
            data: None,
        }
    }

    pub fn with_data(to: &str, data: Vec<u8>) -> Self {
        Self {
            from: None,
            to: String::from(to),
            gas: None,
            gas_price: None,
            value: None,
            data: Some(data),
        }
    }

    pub fn to_json(&self) -> String {
        let mut parts = Vec::new();

        if let Some(ref from) = self.from {
            parts.push(format!(r#""from":"{}""#, from));
        }
        parts.push(format!(r#""to":"{}""#, self.to));

        if let Some(gas) = self.gas {
            parts.push(format!(r#""gas":"0x{:x}""#, gas));
        }
        if let Some(gas_price) = self.gas_price {
            parts.push(format!(r#""gasPrice":"0x{:x}""#, gas_price));
        }
        if let Some(value) = self.value {
            parts.push(format!(r#""value":"0x{:x}""#, value));
        }
        if let Some(ref data) = self.data {
            parts.push(format!(r#""data":"{}""#, bytes_to_hex(data)));
        }

        format!("{{{}}}", parts.join(","))
    }
}

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
    fn from_json(json: &str) -> RpcResult<Self> {
        let tx_hash = extract_json_string(json, "transactionHash").unwrap_or_default();
        let block_number = extract_json_hex_u64(json, "blockNumber").unwrap_or(0);
        let block_hash = extract_json_string(json, "blockHash").unwrap_or_default();
        let gas_used = extract_json_hex_u64(json, "gasUsed").unwrap_or(0);
        let status = extract_json_hex_u64(json, "status").unwrap_or(0) == 1;
        let contract_address = extract_json_string(json, "contractAddress");

        Ok(Self {
            transaction_hash: tx_hash,
            block_number,
            block_hash,
            gas_used,
            status,
            contract_address,
            logs: Vec::new(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Log {
    pub address: String,
    pub topics: Vec<String>,
    pub data: Vec<u8>,
    pub block_number: u64,
    pub transaction_hash: String,
    pub log_index: u64,
}

impl Log {
    fn parse_array(json: &str) -> RpcResult<Vec<Self>> {
        let mut logs = Vec::new();
        let trimmed = json.trim();

        if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
            return Ok(logs);
        }

        // Empty array check
        let inner = trimmed[1..trimmed.len()-1].trim();
        if inner.is_empty() {
            return Ok(logs);
        }

        // Parse each log object in the array
        let mut depth = 0;
        let mut start = 0;
        let bytes = inner.as_bytes();

        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'{' => {
                    if depth == 0 {
                        start = i;
                    }
                    depth += 1;
                }
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        // Found a complete log object
                        let log_json = &inner[start..=i];
                        if let Ok(log) = Self::parse_single(log_json) {
                            logs.push(log);
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(logs)
    }

    fn parse_single(json: &str) -> RpcResult<Self> {
        let address = extract_json_string(json, "address").unwrap_or_default();
        let block_number = extract_json_hex_u64(json, "blockNumber").unwrap_or(0);
        let transaction_hash = extract_json_string(json, "transactionHash").unwrap_or_default();
        let log_index = extract_json_hex_u64(json, "logIndex").unwrap_or(0);

        // Parse topics array
        let mut topics = Vec::new();
        if let Some(topics_start) = json.find("\"topics\"") {
            let rest = &json[topics_start..];
            if let Some(arr_start) = rest.find('[') {
                if let Some(arr_end) = rest.find(']') {
                    let topics_str = &rest[arr_start+1..arr_end];
                    // Parse each topic string
                    let mut in_string = false;
                    let mut topic_start = 0;
                    for (i, c) in topics_str.char_indices() {
                        match c {
                            '"' if !in_string => {
                                in_string = true;
                                topic_start = i + 1;
                            }
                            '"' if in_string => {
                                in_string = false;
                                let topic = &topics_str[topic_start..i];
                                topics.push(String::from(topic));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // Parse data field
        let data_hex = extract_json_string(json, "data").unwrap_or_default();
        let data = hex_to_bytes(&data_hex).unwrap_or_default();

        Ok(Self {
            address,
            topics,
            data,
            block_number,
            transaction_hash,
            log_index,
        })
    }
}

#[derive(Debug, Clone)]
pub struct LogFilter {
    pub from_block: Option<u64>,
    pub to_block: Option<u64>,
    pub address: Option<String>,
    pub topics: Vec<Option<String>>,
}

impl LogFilter {
    pub fn new() -> Self {
        Self {
            from_block: None,
            to_block: None,
            address: None,
            topics: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        let mut parts = Vec::new();

        if let Some(from) = self.from_block {
            parts.push(format!(r#""fromBlock":"0x{:x}""#, from));
        }
        if let Some(to) = self.to_block {
            parts.push(format!(r#""toBlock":"0x{:x}""#, to));
        }
        if let Some(ref addr) = self.address {
            parts.push(format!(r#""address":"{}""#, addr));
        }
        if !self.topics.is_empty() {
            let topics_json: Vec<String> = self
                .topics
                .iter()
                .map(|t| match t {
                    Some(s) => format!(r#""{}""#, s),
                    None => String::from("null"),
                })
                .collect();
            parts.push(format!(r#""topics":[{}]"#, topics_json.join(",")));
        }

        format!("{{{}}}", parts.join(","))
    }
}

impl Default for LogFilter {
    fn default() -> Self {
        Self::new()
    }
}

pub fn balance_of(client: &mut EthRpcClient, token: &str, address: &str) -> RpcResult<u128> {
    let selector = [0x70, 0xa0, 0x82, 0x31];
    let mut data = selector.to_vec();

    let addr_bytes = hex_to_bytes(address)?;
    let mut padded = [0u8; 32];
    padded[12..32].copy_from_slice(&addr_bytes);
    data.extend_from_slice(&padded);

    let call = TransactionCall::with_data(token, data);
    let result = client.eth_call(&call, "latest")?;

    if result.len() < 32 {
        return Ok(0);
    }

    let mut be_bytes = [0u8; 16];
    be_bytes.copy_from_slice(&result[16..32]);
    Ok(u128::from_be_bytes(be_bytes))
}

pub fn allowance(client: &mut EthRpcClient, token: &str, owner: &str, spender: &str) -> RpcResult<u128> {
    let selector = [0xdd, 0x62, 0xed, 0x3e];
    let mut data = selector.to_vec();

    let owner_bytes = hex_to_bytes(owner)?;
    let mut owner_padded = [0u8; 32];
    owner_padded[12..32].copy_from_slice(&owner_bytes);
    data.extend_from_slice(&owner_padded);

    let spender_bytes = hex_to_bytes(spender)?;
    let mut spender_padded = [0u8; 32];
    spender_padded[12..32].copy_from_slice(&spender_bytes);
    data.extend_from_slice(&spender_padded);

    let call = TransactionCall::with_data(token, data);
    let result = client.eth_call(&call, "latest")?;

    if result.len() < 32 {
        return Ok(0);
    }

    let mut be_bytes = [0u8; 16];
    be_bytes.copy_from_slice(&result[16..32]);
    Ok(u128::from_be_bytes(be_bytes))
}

pub fn encode_transfer(to: &str, amount: u128) -> RpcResult<Vec<u8>> {
    let selector = [0xa9, 0x05, 0x9c, 0xbb];
    let mut data = selector.to_vec();

    let to_bytes = hex_to_bytes(to)?;
    let mut to_padded = [0u8; 32];
    to_padded[12..32].copy_from_slice(&to_bytes);
    data.extend_from_slice(&to_padded);

    let amount_bytes = amount.to_be_bytes();
    let mut amount_padded = [0u8; 32];
    amount_padded[16..32].copy_from_slice(&amount_bytes);
    data.extend_from_slice(&amount_padded);

    Ok(data)
}

pub fn encode_approve(spender: &str, amount: u128) -> RpcResult<Vec<u8>> {
    let selector = [0x09, 0x5e, 0xa7, 0xb3];
    let mut data = selector.to_vec();

    let spender_bytes = hex_to_bytes(spender)?;
    let mut spender_padded = [0u8; 32];
    spender_padded[12..32].copy_from_slice(&spender_bytes);
    data.extend_from_slice(&spender_padded);

    let amount_bytes = amount.to_be_bytes();
    let mut amount_padded = [0u8; 32];
    amount_padded[16..32].copy_from_slice(&amount_bytes);
    data.extend_from_slice(&amount_padded);

    Ok(data)
}

fn send_http_post(url: &str, body: &str, timeout_ms: u32) -> RpcResult<String> {
    use crate::network::http;

    let full_url = if url.starts_with("http") {
        String::from(url)
    } else {
        format!("https://{}", url)
    };

    let response = http::post(
        &full_url,
        body.as_bytes(),
        &[("Content-Type", "application/json")],
        timeout_ms,
    )
    .map_err(|_| RpcError::NetworkError)?;

    if response.status_code >= 400 {
        if response.status_code == 429 {
            return Err(RpcError::RateLimited);
        }
        return Err(RpcError::ServerError);
    }

    String::from_utf8(response.body).map_err(|_| RpcError::ParseError)
}

fn parse_json_rpc_response(response: &str) -> RpcResult<String> {
    if let Some(error_start) = response.find(r#""error""#) {
        let error_section = &response[error_start..];
        let code = extract_json_number(error_section, "code").unwrap_or(0);
        return Err(match code {
            -32600 => RpcError::InvalidParams,
            -32601 => RpcError::MethodNotFound,
            -32602 => RpcError::InvalidParams,
            -32603 => RpcError::InternalError,
            _ => RpcError::ServerError,
        });
    }

    extract_json_string(response, "result").ok_or(RpcError::InvalidResponse)
}

fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!(r#""{}":"#, key);
    let start = json.find(&pattern)?;
    let value_start = start + pattern.len();

    if json.as_bytes().get(value_start) == Some(&b'"') {
        let content_start = value_start + 1;
        let content_end = json[content_start..].find('"')?;
        Some(String::from(&json[content_start..content_start + content_end]))
    } else if json.as_bytes().get(value_start) == Some(&b'n') {
        None
    } else {
        let end = json[value_start..]
            .find(|c| c == ',' || c == '}')
            .unwrap_or(json.len() - value_start);
        Some(String::from(&json[value_start..value_start + end]))
    }
}

fn extract_json_number(json: &str, key: &str) -> Option<i64> {
    let pattern = format!(r#""{}":"#, key);
    let start = json.find(&pattern)?;
    let value_start = start + pattern.len();

    let end = json[value_start..]
        .find(|c| c == ',' || c == '}' || c == ' ')
        .unwrap_or(json.len() - value_start);

    json[value_start..value_start + end].parse().ok()
}

fn extract_json_hex_u64(json: &str, key: &str) -> Option<u64> {
    let value = extract_json_string(json, key)?;
    parse_hex_u64(&value).ok()
}

fn parse_hex_u64(hex: &str) -> RpcResult<u64> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    u64::from_str_radix(hex, 16).map_err(|_| RpcError::ParseError)
}

fn parse_hex_u128(hex: &str) -> RpcResult<u128> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    u128::from_str_radix(hex, 16).map_err(|_| RpcError::ParseError)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2 + 2);
    hex.push_str("0x");
    for byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

fn hex_to_bytes(hex: &str) -> RpcResult<Vec<u8>> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);

    if hex.len() % 2 != 0 {
        return Err(RpcError::ParseError);
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| RpcError::ParseError)?;
        bytes.push(byte);
    }

    Ok(bytes)
}

pub fn set_network(network: RpcNetwork) {
    let mut guard = CURRENT_NETWORK.write();
    *guard = network;
}

pub fn get_network() -> RpcNetwork {
    *CURRENT_NETWORK.read()
}

pub fn network_name(network: RpcNetwork) -> String {
    match network {
        RpcNetwork::Mainnet => "mainnet".to_string(),
        RpcNetwork::Sepolia => "sepolia".to_string(),
        RpcNetwork::Localhost => "localhost".to_string(),
    }
}

pub fn format_wei_to_eth(wei: u128) -> String {
    let eth = wei / 1_000_000_000_000_000_000;
    let remainder = (wei % 1_000_000_000_000_000_000) / 1_000_000_000_000_000;
    alloc::format!("{}.{:03}", eth, remainder)
}
