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

use super::types::MAX_PASSWORD_LEN;

pub fn encrypt_password(plaintext: &[u8], encrypted: &mut [u8; MAX_PASSWORD_LEN]) {
    let key = get_encryption_key();
    for (i, &ch) in plaintext.iter().take(MAX_PASSWORD_LEN).enumerate() {
        encrypted[i] = ch ^ key[i % key.len()];
    }
}

pub fn decrypt_password(encrypted: &[u8; MAX_PASSWORD_LEN], plaintext: &mut [u8; MAX_PASSWORD_LEN]) {
    let key = get_encryption_key();
    for i in 0..MAX_PASSWORD_LEN {
        plaintext[i] = encrypted[i] ^ key[i % key.len()];
    }
}

fn get_encryption_key() -> [u8; 32] {
    use crate::crypto::hash::blake3_hash;

    static KEY_SEED: &[u8] = b"NONOS-NETWORK-SETTINGS-KEY-2026";

    if let Some(vault_key) = crate::vault::nonos_vault::NONOS_VAULT.master_key().read().as_ref() {
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&vault_key[..32]);
        input[32..].copy_from_slice(KEY_SEED);
        blake3_hash(&input)
    } else {
        blake3_hash(KEY_SEED)
    }
}

pub fn parse_u8(s: &[u8]) -> Option<u8> {
    let mut result: u8 = 0;
    for &ch in s {
        if ch >= b'0' && ch <= b'9' {
            result = result.saturating_mul(10).saturating_add(ch - b'0');
        } else {
            break;
        }
    }
    if s.is_empty() || (s[0] < b'0' || s[0] > b'9') { None } else { Some(result) }
}

pub fn parse_u16(s: &[u8]) -> Option<u16> {
    let mut result: u16 = 0;
    for &ch in s {
        if ch >= b'0' && ch <= b'9' {
            result = result.saturating_mul(10).saturating_add((ch - b'0') as u16);
        } else {
            break;
        }
    }
    if s.is_empty() || (s[0] < b'0' || s[0] > b'9') { None } else { Some(result) }
}

pub fn parse_bool(s: &[u8]) -> bool {
    !s.is_empty() && (s[0] == b'1' || s[0] == b't' || s[0] == b'T' || s[0] == b'y' || s[0] == b'Y')
}

pub fn parse_ip(s: &[u8]) -> Option<[u8; 4]> {
    let mut ip = [0u8; 4];
    let mut octet = 0;
    let mut val: u16 = 0;

    for &ch in s {
        if ch >= b'0' && ch <= b'9' {
            val = val * 10 + (ch - b'0') as u16;
        } else if ch == b'.' && octet < 3 {
            if val > 255 { return None; }
            ip[octet] = val as u8;
            octet += 1;
            val = 0;
        } else {
            break;
        }
    }

    if octet == 3 && val <= 255 {
        ip[3] = val as u8;
        Some(ip)
    } else {
        None
    }
}

pub fn format_u8(buf: &mut [u8], mut val: u8) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut digits = [0u8; 4];
    let mut pos = 0;
    while val > 0 {
        digits[pos] = b'0' + (val % 10);
        val /= 10;
        pos += 1;
    }
    for i in 0..pos {
        buf[i] = digits[pos - 1 - i];
    }
    pos
}

pub fn format_u16(buf: &mut [u8], mut val: u16) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut digits = [0u8; 6];
    let mut pos = 0;
    while val > 0 {
        digits[pos] = b'0' + (val % 10) as u8;
        val /= 10;
        pos += 1;
    }
    for i in 0..pos {
        buf[i] = digits[pos - 1 - i];
    }
    pos
}

pub fn format_ip(buf: &mut [u8], ip: [u8; 4]) -> usize {
    let mut pos = 0;
    for (i, &octet) in ip.iter().enumerate() {
        let len = format_u8(&mut buf[pos..], octet);
        pos += len;
        if i < 3 && pos < buf.len() {
            buf[pos] = b'.';
            pos += 1;
        }
    }
    pos
}

pub fn hex_char_value(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'A'..=b'F' => c - b'A' + 10,
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    }
}
