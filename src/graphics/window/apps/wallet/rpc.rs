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

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::types::ADDRESS_LEN;

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

const DEFAULT_RPC_HOST: &str = "eth-mainnet.public.blastapi.io";
const DEFAULT_RPC_PORT: u16 = 443;
const USE_HTTPS: bool = true;

#[derive(Debug)]
pub(crate) enum RpcError {
    NetworkError,
    DnsError,
    ParseError,
    InvalidResponse,
    RpcResponseError,
}

fn build_rpc_request(method: &str, params: &str) -> Vec<u8> {
    let id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"{}","params":{},"id":{}}}"#,
        method, params, id
    );

    let mut req = Vec::new();
    req.extend_from_slice(b"POST / HTTP/1.1\r\n");
    req.extend_from_slice(b"Host: ");
    req.extend_from_slice(DEFAULT_RPC_HOST.as_bytes());
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(b"Content-Type: application/json\r\n");
    req.extend_from_slice(b"Content-Length: ");
    req.extend_from_slice(format!("{}", body.len()).as_bytes());
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(b"Connection: close\r\n\r\n");
    req.extend_from_slice(body.as_bytes());
    req
}

fn parse_hex_balance(response: &[u8]) -> Result<u128, RpcError> {
    let result_pattern = b"\"result\":\"0x";
    let mut pos = 0;

    // Check for null result first (invalid response format)
    if response.windows(14).any(|w| w == b"\"result\":null") {
        return Err(RpcError::InvalidResponse);
    }

    while pos + result_pattern.len() < response.len() {
        if &response[pos..pos + result_pattern.len()] == result_pattern {
            let start = pos + result_pattern.len();
            let mut end = start;

            while end < response.len() && response[end] != b'"' {
                end += 1;
            }

            let hex_str = &response[start..end];
            return parse_hex_u128(hex_str);
        }
        pos += 1;
    }

    if response.windows(7).any(|w| w == b"\"error\"") {
        return Err(RpcError::RpcResponseError);
    }

    Err(RpcError::ParseError)
}

fn parse_hex_u128(hex: &[u8]) -> Result<u128, RpcError> {
    let mut value: u128 = 0;

    for &b in hex {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(RpcError::ParseError),
        };
        value = value.checked_mul(16).ok_or(RpcError::ParseError)?;
        value = value.checked_add(digit as u128).ok_or(RpcError::ParseError)?;
    }

    Ok(value)
}

fn format_address_hex(address: &[u8; ADDRESS_LEN]) -> String {
    let mut hex = String::from("0x");
    for byte in address {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

pub(crate) fn fetch_balance(address: &[u8; ADDRESS_LEN]) -> Result<u128, RpcError> {
    let addr_hex = format_address_hex(address);
    let params = format!(r#"["{}","latest"]"#, addr_hex);
    let request = build_rpc_request("eth_getBalance", &params);

    let response = send_rpc_request(&request)?;
    parse_hex_balance(&response)
}

fn send_rpc_request(request: &[u8]) -> Result<Vec<u8>, RpcError> {
    let ip = crate::network::dns::resolve_v4(DEFAULT_RPC_HOST)
        .map_err(|_| RpcError::DnsError)?;

    let ns = crate::network::get_network_stack()
        .ok_or(RpcError::NetworkError)?;

    if USE_HTTPS {
        ns.https_request(ip, DEFAULT_RPC_PORT, DEFAULT_RPC_HOST, request, 30_000)
            .map_err(|_| RpcError::NetworkError)
    } else {
        ns.http_request(ip, 80, request)
            .map_err(|_| RpcError::NetworkError)
    }
}

pub(crate) fn fetch_nonce(address: &[u8; ADDRESS_LEN]) -> Result<u64, RpcError> {
    let addr_hex = format_address_hex(address);
    let params = format!(r#"["{}","pending"]"#, addr_hex);
    let request = build_rpc_request("eth_getTransactionCount", &params);

    let response = send_rpc_request(&request)?;
    let balance = parse_hex_balance(&response)?;
    Ok(balance as u64)
}

pub(crate) fn fetch_gas_price() -> Result<u128, RpcError> {
    let request = build_rpc_request("eth_gasPrice", "[]");
    let response = send_rpc_request(&request)?;
    parse_hex_balance(&response)
}

pub(crate) fn send_raw_transaction(signed_tx: &[u8]) -> Result<[u8; 32], RpcError> {
    let mut tx_hex = String::from("0x");
    for byte in signed_tx {
        tx_hex.push_str(&format!("{:02x}", byte));
    }

    let params = format!(r#"["{}"]"#, tx_hex);
    let request = build_rpc_request("eth_sendRawTransaction", &params);
    let response = send_rpc_request(&request)?;

    parse_tx_hash(&response)
}

fn parse_tx_hash(response: &[u8]) -> Result<[u8; 32], RpcError> {
    let result_pattern = b"\"result\":\"0x";
    let mut pos = 0;

    while pos + result_pattern.len() < response.len() {
        if &response[pos..pos + result_pattern.len()] == result_pattern {
            let start = pos + result_pattern.len();

            if start + 64 > response.len() {
                return Err(RpcError::ParseError);
            }

            let hex_str = &response[start..start + 64];
            let mut hash = [0u8; 32];

            for i in 0..32 {
                let hi = hex_digit(hex_str[i * 2])?;
                let lo = hex_digit(hex_str[i * 2 + 1])?;
                hash[i] = (hi << 4) | lo;
            }

            return Ok(hash);
        }
        pos += 1;
    }

    Err(RpcError::ParseError)
}

fn hex_digit(c: u8) -> Result<u8, RpcError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(RpcError::ParseError),
    }
}

pub(crate) fn fetch_block_number() -> Result<u64, RpcError> {
    let request = build_rpc_request("eth_blockNumber", "[]");
    let response = send_rpc_request(&request)?;
    let value = parse_hex_balance(&response)?;
    Ok(value as u64)
}

pub(crate) fn is_rpc_available() -> bool {
    crate::network::is_network_available()
}
