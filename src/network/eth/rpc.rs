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
use alloc::string::String;
use alloc::vec::Vec;

pub const MAINNET_RPC: &str = "https://eth.llamarpc.com";
pub const BASE_RPC: &str = "https://mainnet.base.org";
pub const CHAIN_MAINNET: u64 = 1;
pub const CHAIN_BASE: u64 = 8453;

#[derive(Debug)]
pub enum RpcError { Network, Parse, Sign, Revert(String) }

pub fn json_rpc(url: &str, method: &str, params: &str) -> Result<Vec<u8>, RpcError> {
    let body = alloc::format!(r#"{{"jsonrpc":"2.0","method":"{}","params":{},"id":1}}"#, method, params);
    crate::network::http::post_json(url, body.as_bytes()).map_err(|_| RpcError::Network)
}

pub fn eth_call(url: &str, to: &[u8; 20], data: &[u8]) -> Result<Vec<u8>, RpcError> {
    let to_hex = hex_encode(to);
    let data_hex = hex_encode(data);
    let params = alloc::format!(r#"[{{"to":"0x{}","data":"0x{}"}},"latest"]"#, to_hex, data_hex);
    let resp = json_rpc(url, "eth_call", &params)?;
    parse_hex_result(&resp)
}

pub fn eth_send_raw(url: &str, signed_tx: &[u8]) -> Result<[u8; 32], RpcError> {
    let tx_hex = hex_encode(signed_tx);
    let params = alloc::format!(r#"["0x{}"]"#, tx_hex);
    let resp = json_rpc(url, "eth_sendRawTransaction", &params)?;
    let hash = parse_hex_result(&resp)?;
    if hash.len() != 32 { return Err(RpcError::Parse); }
    let mut h = [0u8; 32];
    h.copy_from_slice(&hash);
    Ok(h)
}

pub fn eth_get_balance(url: &str, addr: &[u8; 20]) -> Result<u128, RpcError> {
    let addr_hex = hex_encode(addr);
    let params = alloc::format!(r#"["0x{}","latest"]"#, addr_hex);
    let resp = json_rpc(url, "eth_getBalance", &params)?;
    let bytes = parse_hex_result(&resp)?;
    Ok(bytes_to_u128(&bytes))
}

pub fn eth_get_nonce(url: &str, addr: &[u8; 20]) -> Result<u64, RpcError> {
    let addr_hex = hex_encode(addr);
    let params = alloc::format!(r#"["0x{}","latest"]"#, addr_hex);
    let resp = json_rpc(url, "eth_getTransactionCount", &params)?;
    let bytes = parse_hex_result(&resp)?;
    Ok(bytes_to_u128(&bytes) as u64)
}

pub fn eth_gas_price(url: &str) -> Result<u128, RpcError> {
    let resp = json_rpc(url, "eth_gasPrice", "[]")?;
    let bytes = parse_hex_result(&resp)?;
    Ok(bytes_to_u128(&bytes))
}

fn parse_hex_result(resp: &[u8]) -> Result<Vec<u8>, RpcError> {
    let s = core::str::from_utf8(resp).map_err(|_| RpcError::Parse)?;
    if let Some(i) = s.find("\"result\":\"0x") {
        let start = i + 12;
        let end = s[start..].find('"').ok_or(RpcError::Parse)? + start;
        return hex_decode(&s[start..end]);
    }
    if s.contains("\"error\"") { return Err(RpcError::Revert(s.into())); }
    Err(RpcError::Parse)
}

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data { s.push_str(&alloc::format!("{:02x}", b)); }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, RpcError> {
    if s.len() % 2 != 0 { return Err(RpcError::Parse); }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i+2], 16).map_err(|_| RpcError::Parse)?);
    }
    Ok(out)
}

fn bytes_to_u128(b: &[u8]) -> u128 {
    let mut v = 0u128;
    for &byte in b { v = (v << 8) | byte as u128; }
    v
}
