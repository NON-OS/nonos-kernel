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
use super::rpc_endpoints::get_endpoints;
use super::rpc_parse::{format_address_hex, parse_call_result, parse_hex_balance, parse_tx_hash};
use super::types::ADDRESS_LEN;
use alloc::{format, vec::Vec};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

static REQ_ID: AtomicU64 = AtomicU64::new(1);
static CUR_EP: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
pub(crate) enum RpcError {
    NetworkError,
    ParseError,
    InvalidResponse,
    RpcResponseError,
}

fn build_req(m: &str, p: &str) -> Vec<u8> {
    format!(
        r#"{{"jsonrpc":"2.0","method":"{}","params":{},"id":{}}}"#,
        m,
        p,
        REQ_ID.fetch_add(1, Ordering::Relaxed)
    )
    .into_bytes()
}

fn send_req(req: &[u8]) -> Result<Vec<u8>, RpcError> {
    let ns = crate::network::get_network_stack().ok_or(RpcError::NetworkError)?;
    let eps = get_endpoints();
    let si = CUR_EP.load(Ordering::Relaxed);
    for o in 0..eps.len() {
        let i = (si + o) % eps.len();
        let ep = &eps[i];
        let ip = crate::network::dns::resolve_v4(ep.host).unwrap_or_else(|_| {
            if ep.fallback_ips.is_empty() {
                [0; 4]
            } else {
                ep.fallback_ips[0]
            }
        });
        let mut r = Vec::new();
        r.extend_from_slice(b"POST / HTTP/1.1\r\nHost: ");
        r.extend_from_slice(ep.host.as_bytes());
        r.extend_from_slice(b"\r\nContent-Type: application/json\r\nContent-Length: ");
        r.extend_from_slice(format!("{}", req.len()).as_bytes());
        r.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
        r.extend_from_slice(req);
        if let Ok(res) = ns.https_request(ip, ep.port, ep.host, &r, 2000) {
            CUR_EP.store(i, Ordering::Relaxed);
            return Ok(res);
        }
        for &fb in ep.fallback_ips {
            if let Ok(res) = ns.https_request(fb, ep.port, ep.host, &r, 2000) {
                CUR_EP.store(i, Ordering::Relaxed);
                return Ok(res);
            }
        }
    }
    Err(RpcError::NetworkError)
}

pub(crate) fn fetch_balance(a: &[u8; ADDRESS_LEN]) -> Result<u128, RpcError> {
    parse_hex_balance(&send_req(&build_req(
        "eth_getBalance",
        &format!(r#"["{}","latest"]"#, format_address_hex(a)),
    ))?)
}
pub(crate) fn fetch_nonce(a: &[u8; ADDRESS_LEN]) -> Result<u64, RpcError> {
    Ok(parse_hex_balance(&send_req(&build_req(
        "eth_getTransactionCount",
        &format!(r#"["{}","pending"]"#, format_address_hex(a)),
    ))?)? as u64)
}
pub(crate) fn fetch_gas_price() -> Result<u128, RpcError> {
    parse_hex_balance(&send_req(&build_req("eth_gasPrice", "[]"))?)
}
pub(crate) fn fetch_block_number() -> Result<u64, RpcError> {
    Ok(parse_hex_balance(&send_req(&build_req("eth_blockNumber", "[]"))?)? as u64)
}
pub(crate) fn is_rpc_available() -> bool {
    crate::network::is_network_available()
}

pub(crate) fn send_raw_transaction(tx: &[u8]) -> Result<[u8; 32], RpcError> {
    let mut h = alloc::string::String::from("0x");
    for b in tx {
        h.push_str(&format!("{:02x}", b));
    }
    parse_tx_hash(&send_req(&build_req("eth_sendRawTransaction", &format!(r#"["{}"]"#, h)))?)
}

pub(crate) fn fetch_token_balance(
    c: &[u8; ADDRESS_LEN],
    o: &[u8; ADDRESS_LEN],
) -> Result<u128, RpcError> {
    let d = format!("0x70a08231000000000000000000000000{}", &format_address_hex(o)[2..]);
    parse_hex_balance(&send_req(&build_req(
        "eth_call",
        &format!(r#"[{{"to":"{}","data":"{}"}},"latest"]"#, format_address_hex(c), d),
    ))?)
}

pub(crate) fn eth_call(contract: &[u8; ADDRESS_LEN], data: &[u8]) -> Result<Vec<u8>, RpcError> {
    let mut d = alloc::string::String::from("0x");
    for b in data {
        d.push_str(&format!("{:02x}", b));
    }
    let res = send_req(&build_req(
        "eth_call",
        &format!(r#"[{{"to":"{}","data":"{}"}},"latest"]"#, format_address_hex(contract), d),
    ))?;
    parse_call_result(&res)
}
