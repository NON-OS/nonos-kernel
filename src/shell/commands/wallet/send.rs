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

/* sends eth/tokens using real transaction signing and rpc broadcast */

extern crate alloc;

use crate::apps::ecosystem::wallet::rpc::{format_wei_to_eth, get_network, EthRpcClient};
use crate::apps::ecosystem::wallet::transaction::{build_transaction, sign_transaction};
use crate::display::framebuffer::{COLOR_ACCENT, COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW};
use crate::graphics::window::apps::wallet::WALLET_STATE;
use crate::shell::output::print_line;
use alloc::vec::Vec;

use super::util::trim_bytes;

pub fn cmd_wallet_send(cmd: &[u8]) {
    let state = WALLET_STATE.lock();
    if !state.unlocked {
        drop(state);
        print_line(b"Wallet locked", COLOR_RED);
        return;
    }

    let account = match state.get_active_account() {
        Some(acc) => acc,
        None => {
            drop(state);
            print_line(b"No active account", COLOR_RED);
            return;
        }
    };

    let secret_key = account.secret_key;
    let from_addr = account.address;
    drop(state);

    let args = if cmd.len() > 12 {
        trim_bytes(&cmd[12..])
    } else {
        print_line(b"Usage: wallet-send <addr> <amount>", COLOR_TEXT_DIM);
        return;
    };

    if args.is_empty() {
        print_line(b"Missing address and amount", COLOR_RED);
        return;
    }

    let (to_addr, amount_wei) = match parse_send_args(args) {
        Some(parsed) => parsed,
        None => {
            print_line(b"Invalid address or amount", COLOR_RED);
            return;
        }
    };

    print_line(b"Building Transaction...", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);

    let network = get_network();
    let chain_id = network.chain_id();
    let mut client = EthRpcClient::new(network);

    let from_hex = addr_to_hex(&from_addr);
    let nonce = match client.get_transaction_count(&from_hex) {
        Ok(n) => n,
        Err(_) => {
            print_line(b"Failed to fetch nonce", COLOR_RED);
            return;
        }
    };

    let (max_fee, priority_fee) = match fetch_gas_prices(&mut client) {
        Some(fees) => fees,
        None => {
            print_line(b"Failed to fetch gas prices", COLOR_RED);
            return;
        }
    };

    let gas_limit = 21000u64;
    let tx = build_transaction(
        &to_addr,
        amount_wei,
        Vec::new(),
        nonce,
        gas_limit,
        max_fee,
        priority_fee,
        chain_id,
    );

    print_line(b"Signing...", COLOR_TEXT);
    let signed = match sign_transaction(&tx, &secret_key) {
        Ok(s) => s,
        Err(_) => {
            print_line(b"Signing failed", COLOR_RED);
            return;
        }
    };

    print_line(b"Broadcasting...", COLOR_TEXT);
    match client.send_raw_transaction(&signed.raw) {
        Ok(tx_hash) => {
            print_line(b"", COLOR_TEXT);
            print_line(b"Transaction Sent", COLOR_GREEN);
            print_line(b"================================", COLOR_TEXT_DIM);
            print_tx_hash(&tx_hash);
            print_line(b"", COLOR_TEXT);

            let amount_eth = format_wei_to_eth(amount_wei);
            print_amount(&amount_eth);
            print_line(b"Status: PENDING", COLOR_YELLOW);
        }
        Err(e) => {
            print_line(b"Broadcast failed", COLOR_RED);
            print_rpc_error(e);
        }
    }
}

fn parse_send_args(args: &[u8]) -> Option<([u8; 20], u128)> {
    let mut parts = args.split(|&b| b == b' ');

    let addr_bytes = parts.next()?;
    let amount_bytes = parts.next()?;

    if addr_bytes.len() < 40 {
        return None;
    }

    let addr_hex = if addr_bytes.starts_with(b"0x") { &addr_bytes[2..] } else { addr_bytes };

    if addr_hex.len() != 40 {
        return None;
    }

    let mut to_addr = [0u8; 20];
    for i in 0..20 {
        let high = hex_digit(addr_hex[i * 2])?;
        let low = hex_digit(addr_hex[i * 2 + 1])?;
        to_addr[i] = (high << 4) | low;
    }

    let amount_wei = parse_amount(amount_bytes)?;

    Some((to_addr, amount_wei))
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_amount(bytes: &[u8]) -> Option<u128> {
    let mut val: u128 = 0;
    let mut decimals: i32 = -1;
    let mut decimal_count = 0;

    for &b in bytes {
        match b {
            b'0'..=b'9' => {
                val = val.checked_mul(10)?.checked_add((b - b'0') as u128)?;
                if decimals >= 0 {
                    decimal_count += 1;
                }
            }
            b'.' => {
                if decimals >= 0 {
                    return None;
                }
                decimals = 0;
            }
            _ => return None,
        }
    }

    let missing_decimals = 18 - decimal_count;
    for _ in 0..missing_decimals {
        val = val.checked_mul(10)?;
    }

    Some(val)
}

fn addr_to_hex(addr: &[u8; 20]) -> alloc::string::String {
    use alloc::string::String;
    let mut hex = String::with_capacity(42);
    hex.push_str("0x");
    for byte in addr {
        hex.push_str(&alloc::format!("{:02x}", byte));
    }
    hex
}

fn fetch_gas_prices(client: &mut EthRpcClient) -> Option<(u128, u128)> {
    let base_fee = client.get_gas_price().ok()?;
    let priority_fee = client.get_max_priority_fee().unwrap_or(2_000_000_000);

    let max_fee = base_fee.saturating_mul(2).saturating_add(priority_fee);
    Some((max_fee, priority_fee))
}

fn print_tx_hash(hash: &str) {
    let msg = alloc::format!("TxHash: {}", hash);
    print_line(msg.as_bytes(), COLOR_ACCENT);
}

fn print_amount(eth: &str) {
    let msg = alloc::format!("Amount: {} ETH", eth);
    print_line(msg.as_bytes(), COLOR_TEXT);
}

fn print_rpc_error(e: crate::apps::ecosystem::wallet::rpc::RpcError) {
    use crate::apps::ecosystem::wallet::rpc::RpcError;
    let msg = match e {
        RpcError::InsufficientFunds => b"Insufficient funds" as &[u8],
        RpcError::NonceTooLow => b"Nonce too low",
        RpcError::GasTooLow => b"Gas too low",
        RpcError::NetworkError => b"Network error",
        RpcError::RateLimited => b"Rate limited",
        _ => b"Transaction rejected",
    };
    print_line(msg, COLOR_RED);
}
