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

use crate::shell::commands::wallet::*;
use crate::shell::commands::node::*;
use crate::shell::commands::apps::cmd_open_wallet;
use crate::shell::commands::utils::starts_with;

pub fn try_dispatch_blockchain(cmd: &[u8]) -> bool {
    if cmd == b"wallet" || cmd == b"wallet-status" {
        cmd_wallet_status();
    } else if cmd == b"wallet-new" || cmd == b"wallet-create" {
        cmd_wallet_new();
    } else if cmd == b"wallet-unlock" || starts_with(cmd, b"wallet-unlock ") {
        cmd_wallet_unlock(cmd);
    } else if cmd == b"wallet-lock" {
        cmd_wallet_lock();
    } else if cmd == b"wallet-address" || cmd == b"wallet-addr" {
        cmd_wallet_address();
    } else if cmd == b"wallet-balance" || cmd == b"wallet-bal" {
        cmd_wallet_balance();
    } else if cmd == b"wallet-send" || starts_with(cmd, b"wallet-send ") {
        cmd_wallet_send(cmd);
    } else if cmd == b"wallet-derive" {
        cmd_wallet_derive(cmd);
    } else if cmd == b"wallet-stealth" {
        cmd_wallet_stealth();
    } else if cmd == b"wallet-sign" || starts_with(cmd, b"wallet-sign ") {
        cmd_wallet_sign(cmd);
    } else if cmd == b"wallet-export" {
        cmd_wallet_export();
    } else if cmd == b"wallet-help" {
        cmd_wallet_help();
    } else if cmd == b"wallet-gui" {
        cmd_open_wallet();
    } else if cmd == b"node" || cmd == b"node-status" {
        cmd_node_status();
    } else if cmd == b"node-init" {
        cmd_node_init();
    } else if cmd == b"node-start" {
        cmd_node_start();
    } else if cmd == b"node-stop" {
        cmd_node_stop();
    } else if cmd == b"stake" || cmd == b"stake-status" {
        cmd_stake_status();
    } else if cmd == b"stake-deposit" || starts_with(cmd, b"stake-deposit ") {
        cmd_stake_deposit(cmd);
    } else if cmd == b"rewards-claim" || cmd == b"claim" {
        cmd_rewards_claim();
    } else if cmd == b"peers" || cmd == b"peers-list" {
        cmd_peers_list();
    } else if cmd == b"mixer" || cmd == b"mixer-status" {
        cmd_mixer_status();
    } else if cmd == b"identity" || cmd == b"identity-list" {
        cmd_identity_list();
    } else if cmd == b"identity-new" {
        cmd_identity_new();
    } else if cmd == b"node-help" {
        cmd_node_help();
    } else {
        return false;
    }
    true
}
