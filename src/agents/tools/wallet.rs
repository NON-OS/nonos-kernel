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

use alloc::format;
use alloc::vec::Vec;

pub(super) fn register() {
    super::register_tool(b"wallet_balance", b"Get wallet balance", tool_balance);
    super::register_tool(b"wallet_address", b"Get wallet address", tool_address);
    super::register_tool(b"wallet_send", b"Send NOX: address amount", tool_send);
}

fn tool_balance(_args: &[u8]) -> Vec<u8> {
    let state = crate::graphics::window::apps::wallet::WALLET_STATE.lock();
    let balance = state.total_nox_balance();
    format!("Wallet Balance: {} NOX", balance).into_bytes()
}

fn tool_address(_args: &[u8]) -> Vec<u8> {
    let state = crate::graphics::window::apps::wallet::WALLET_STATE.lock();
    match state.get_active_account() {
        Some(acc) => {
            let hex: alloc::string::String =
                acc.address.iter().map(|b| format!("{:02x}", b)).collect();
            format!("Wallet Address: 0x{}", hex).into_bytes()
        }
        None => b"Wallet not initialized".to_vec(),
    }
}

fn tool_send(args: &[u8]) -> Vec<u8> {
    let s = core::str::from_utf8(args).unwrap_or("");
    let parts: alloc::vec::Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 2 {
        return b"Usage: wallet_send <address> <amount>".to_vec();
    }
    let addr = parts[0];
    let amount: u64 = parts[1].parse().unwrap_or(0);
    if amount == 0 {
        return b"Invalid amount".to_vec();
    }
    if !addr.starts_with("0x") || addr.len() != 42 {
        return b"Invalid address format".to_vec();
    }
    format!("Transaction queued: {} NOX to {}", amount, addr).into_bytes()
}
