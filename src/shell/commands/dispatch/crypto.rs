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

use crate::shell::commands::cryptography::*;
use crate::shell::commands::security::*;
use crate::shell::commands::vault::*;
use crate::shell::commands::utils::starts_with;

pub fn try_dispatch_crypto(cmd: &[u8]) -> bool {
    if cmd == b"hash" || starts_with(cmd, b"hash ") {
        cmd_hash(cmd);
    } else if cmd == b"random" || starts_with(cmd, b"random ") {
        cmd_random(cmd);
    } else if cmd == b"genkey" || starts_with(cmd, b"genkey ") {
        cmd_genkey(cmd);
    } else if cmd == b"crypto" {
        cmd_crypto_status();
    } else if cmd == b"hmac" || starts_with(cmd, b"hmac ") {
        cmd_hmac(cmd);
    } else if cmd == b"audit" {
        cmd_audit();
    } else if cmd == b"caps" || cmd == b"capabilities" {
        cmd_caps();
    } else if cmd == b"firewall" || starts_with(cmd, b"firewall ") {
        cmd_firewall(cmd);
    } else if cmd == b"secstatus" || cmd == b"security" {
        cmd_secstatus();
    } else if cmd == b"rootkit-scan" || cmd == b"rkhunter" {
        cmd_rootkit_scan();
    } else if cmd == b"integrity" {
        cmd_integrity();
    } else if cmd == b"sessions" {
        cmd_sessions();
    } else if cmd == b"locks" {
        cmd_locks();
    } else if cmd == b"vault" {
        cmd_vault_status();
    } else if cmd == b"vault-seal" {
        cmd_vault_seal();
    } else if cmd == b"vault-unseal" || starts_with(cmd, b"vault-unseal ") {
        cmd_vault_unseal(cmd);
    } else if cmd == b"vault-derive" || starts_with(cmd, b"vault-derive ") {
        cmd_vault_derive(cmd);
    } else if cmd == b"vault-keys" {
        cmd_vault_keys();
    } else if cmd == b"vault-erase" {
        cmd_vault_erase();
    } else if cmd == b"vault-policy" {
        cmd_vault_policy();
    } else if cmd == b"vault-audit" {
        cmd_vault_audit();
    } else if cmd == b"vault-sign" || starts_with(cmd, b"vault-sign ") {
        cmd_vault_sign(cmd);
    } else if cmd == b"vault-verify" || starts_with(cmd, b"vault-verify ") {
        cmd_vault_verify(cmd);
    } else if cmd == b"vault-encrypt" || starts_with(cmd, b"vault-encrypt ") {
        cmd_vault_encrypt(cmd);
    } else if cmd == b"vault-decrypt" || starts_with(cmd, b"vault-decrypt ") {
        cmd_vault_decrypt(cmd);
    } else {
        return false;
    }
    true
}
