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
use super::types::{RpcError, RpcResult};
use alloc::{format, string::String, vec::Vec};

pub(super) fn send_http_post(url: &str, body: &str, timeout_ms: u32) -> RpcResult<String> {
    use crate::network::http;
    let full_url =
        if url.starts_with("http") { String::from(url) } else { format!("https://{}", url) };
    let response =
        http::post(&full_url, body.as_bytes(), &[("Content-Type", "application/json")], timeout_ms)
            .map_err(|_| RpcError::NetworkError)?;
    if response.status_code == 429 {
        return Err(RpcError::RateLimited);
    }
    if response.status_code >= 400 {
        return Err(RpcError::ServerError);
    }
    String::from_utf8(response.body).map_err(|_| RpcError::ParseError)
}

pub(super) fn parse_json_rpc_response(response: &str) -> RpcResult<String> {
    if let Some(error_start) = response.find(r#""error""#) {
        let code = extract_json_number(&response[error_start..], "code").unwrap_or(0);
        return Err(match code {
            -32600 | -32602 => RpcError::InvalidParams,
            -32601 => RpcError::MethodNotFound,
            -32603 => RpcError::InternalError,
            _ => RpcError::ServerError,
        });
    }
    extract_json_string(response, "result").ok_or(RpcError::InvalidResponse)
}

pub(super) fn extract_json_string(json: &str, key: &str) -> Option<String> {
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
        let end =
            json[value_start..].find(|c| c == ',' || c == '}').unwrap_or(json.len() - value_start);
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

pub(super) fn extract_json_hex_u64(json: &str, key: &str) -> Option<u64> {
    parse_hex_u64(&extract_json_string(json, key)?).ok()
}
pub(super) fn parse_hex_u64(hex: &str) -> RpcResult<u64> {
    u64::from_str_radix(hex.strip_prefix("0x").unwrap_or(hex), 16).map_err(|_| RpcError::ParseError)
}
pub(super) fn parse_hex_u128(hex: &str) -> RpcResult<u128> {
    u128::from_str_radix(hex.strip_prefix("0x").unwrap_or(hex), 16)
        .map_err(|_| RpcError::ParseError)
}

pub(super) fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2 + 2);
    hex.push_str("0x");
    for byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

pub(super) fn hex_to_bytes(hex: &str) -> RpcResult<Vec<u8>> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() % 2 != 0 {
        return Err(RpcError::ParseError);
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| RpcError::ParseError)?);
    }
    Ok(bytes)
}
