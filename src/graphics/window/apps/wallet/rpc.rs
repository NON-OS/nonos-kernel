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
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::types::ADDRESS_LEN;
use super::network::{get_network, NetworkId};

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);
static CURRENT_ENDPOINT: AtomicUsize = AtomicUsize::new(0);

struct RpcEndpoint {
    host: &'static str,
    port: u16,
    fallback_ips: &'static [[u8; 4]],
}

const MAINNET_ENDPOINTS: &[RpcEndpoint] = &[
    RpcEndpoint {
        host: "ethereum.publicnode.com",
        port: 443,
        fallback_ips: &[[65, 109, 115, 36], [65, 109, 115, 37]],
    },
    RpcEndpoint {
        host: "1rpc.io",
        port: 443,
        fallback_ips: &[[52, 77, 91, 106]],
    },
    RpcEndpoint {
        host: "eth.merkle.io",
        port: 443,
        fallback_ips: &[[104, 21, 64, 15]],
    },
];

const SEPOLIA_ENDPOINTS: &[RpcEndpoint] = &[
    RpcEndpoint {
        host: "ethereum-sepolia-rpc.publicnode.com",
        port: 443,
        fallback_ips: &[[65, 109, 115, 38], [65, 109, 115, 39]],
    },
    RpcEndpoint {
        host: "rpc.sepolia.org",
        port: 443,
        fallback_ips: &[[65, 108, 79, 140]],
    },
    RpcEndpoint {
        host: "sepolia.drpc.org",
        port: 443,
        fallback_ips: &[[172, 67, 182, 156]],
    },
];

fn get_endpoints() -> &'static [RpcEndpoint] {
    match get_network() {
        NetworkId::Mainnet => MAINNET_ENDPOINTS,
        NetworkId::Sepolia => SEPOLIA_ENDPOINTS,
    }
}

#[derive(Debug)]
pub(crate) enum RpcError {
    NetworkError,
    ParseError,
    InvalidResponse,
    RpcResponseError,
}

fn build_rpc_request(method: &str, params: &str) -> Vec<u8> {
    let id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    format!(
        r#"{{"jsonrpc":"2.0","method":"{}","params":{},"id":{}}}"#,
        method, params, id
    ).into_bytes()
}

fn parse_hex_balance(response: &[u8]) -> Result<u128, RpcError> {
    let result_pattern = b"\"result\":\"0x";
    let mut pos = 0;

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
    let ns = crate::network::get_network_stack()
        .ok_or(RpcError::NetworkError)?;

    let endpoints = get_endpoints();
    let start_idx = CURRENT_ENDPOINT.load(Ordering::Relaxed);

    for offset in 0..endpoints.len() {
        let idx = (start_idx + offset) % endpoints.len();
        let endpoint = &endpoints[idx];

        let ip = match crate::network::dns::resolve_v4(endpoint.host) {
            Ok(resolved) => resolved,
            Err(_) => {
                if endpoint.fallback_ips.is_empty() {
                    continue;
                }
                endpoint.fallback_ips[0]
            }
        };

        let req_with_host = build_rpc_request_for_host(request, endpoint.host);

        match ns.https_request(ip, endpoint.port, endpoint.host, &req_with_host, 2_000) {
            Ok(response) => {
                CURRENT_ENDPOINT.store(idx, Ordering::Relaxed);
                return Ok(response);
            }
            Err(_) => {
                for &fallback_ip in endpoint.fallback_ips {
                    if let Ok(response) = ns.https_request(fallback_ip, endpoint.port, endpoint.host, &req_with_host, 2_000) {
                        CURRENT_ENDPOINT.store(idx, Ordering::Relaxed);
                        return Ok(response);
                    }
                }
            }
        }
    }

    Err(RpcError::NetworkError)
}

fn build_rpc_request_for_host(body: &[u8], host: &str) -> Vec<u8> {
    let mut req = Vec::new();
    req.extend_from_slice(b"POST / HTTP/1.1\r\nHost: ");
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(b"\r\nContent-Type: application/json\r\nContent-Length: ");
    req.extend_from_slice(format!("{}", body.len()).as_bytes());
    req.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    req.extend_from_slice(body);
    req
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

pub(crate) fn fetch_token_balance(
    token_contract: &[u8; ADDRESS_LEN],
    owner: &[u8; ADDRESS_LEN],
) -> Result<u128, RpcError> {
    let contract_hex = format_address_hex(token_contract);
    let owner_hex = format_address_hex(owner);
    let owner_padded = &owner_hex[2..];

    let data = format!(
        "0x70a08231000000000000000000000000{}",
        owner_padded
    );

    let params = format!(
        r#"[{{"to":"{}","data":"{}"}},"latest"]"#,
        contract_hex, data
    );
    let request = build_rpc_request("eth_call", &params);

    let response = send_rpc_request(&request)?;
    parse_hex_balance(&response)
}
