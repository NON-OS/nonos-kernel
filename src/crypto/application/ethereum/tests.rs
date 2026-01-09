// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::*;
use crate::crypto::application::ethereum::rlp::{rlp_encode_length, trim_leading_zeros};
#[test]
fn test_hex_digit_numeric() {
    assert_eq!(hex_digit(b'0'), 0);
    assert_eq!(hex_digit(b'5'), 5);
    assert_eq!(hex_digit(b'9'), 9);
}

#[test]
fn test_hex_digit_lowercase() {
    assert_eq!(hex_digit(b'a'), 10);
    assert_eq!(hex_digit(b'f'), 15);
}

#[test]
fn test_hex_digit_uppercase() {
    assert_eq!(hex_digit(b'A'), 10);
    assert_eq!(hex_digit(b'F'), 15);
}

#[test]
fn test_nox_token_address() {
    assert_eq!(NOX_TOKEN_ADDRESS[0], 0x0a);
    assert_eq!(NOX_TOKEN_ADDRESS[1], 0x26);
    assert_eq!(NOX_TOKEN_ADDRESS[19], 0xCA);
}

#[test]
fn test_eth_address_from_bytes() {
    let bytes = [0u8; 20];
    let addr = EthAddress::from_bytes(&bytes);
    assert_eq!(addr.to_bytes(), bytes);
}

#[test]
fn test_eth_address_checksum_all_zeros() {
    let addr = EthAddress([0u8; 20]);
    let checksum = addr.to_checksum_string();
    assert_eq!(&checksum[0..2], b"0x");
    for &c in &checksum[2..] {
        assert!(c == b'0');
    }
}

#[test]
fn test_eth_address_checksum_format() {
    let addr = EthAddress(NOX_TOKEN_ADDRESS);
    let checksum = addr.to_checksum_string();
    assert_eq!(&checksum[0..2], b"0x");
    assert_eq!(checksum.len(), 42);
}

#[test]
fn test_rlp_encode_u64_zero() {
    let encoded = rlp_encode_u64(0);
    assert_eq!(encoded, vec![0x80]);
}

#[test]
fn test_rlp_encode_u64_small() {
    assert_eq!(rlp_encode_u64(1), vec![0x01]);
    assert_eq!(rlp_encode_u64(127), vec![0x7f]);
}

#[test]
fn test_rlp_encode_u64_medium() {
    let encoded = rlp_encode_u64(128);
    assert_eq!(encoded, vec![0x81, 0x80]);
}

#[test]
fn test_rlp_encode_u64_large() {
    let encoded = rlp_encode_u64(256);
    assert_eq!(encoded, vec![0x82, 0x01, 0x00]);
}

#[test]
fn test_rlp_encode_u128_zero() {
    let encoded = rlp_encode_u128(0);
    assert_eq!(encoded, vec![0x80]);
}

#[test]
fn test_rlp_encode_u128_small() {
    assert_eq!(rlp_encode_u128(1), vec![0x01]);
    assert_eq!(rlp_encode_u128(127), vec![0x7f]);
}

#[test]
fn test_rlp_encode_bytes_empty() {
    let encoded = rlp_encode_bytes(&[]);
    assert_eq!(encoded, vec![0x80]);
}

#[test]
fn test_rlp_encode_bytes_single_small() {
    let encoded = rlp_encode_bytes(&[0x05]);
    assert_eq!(encoded, vec![0x05]);
}

#[test]
fn test_rlp_encode_bytes_single_large() {
    let encoded = rlp_encode_bytes(&[0x80]);
    assert_eq!(encoded, vec![0x81, 0x80]);
}

#[test]
fn test_rlp_encode_bytes_multiple() {
    let encoded = rlp_encode_bytes(&[0x01, 0x02, 0x03]);
    assert_eq!(encoded, vec![0x83, 0x01, 0x02, 0x03]);
}

#[test]
fn test_rlp_encode_list_empty() {
    let encoded = rlp_encode_list(&[]);
    assert_eq!(encoded, vec![0xc0]);
}

#[test]
fn test_rlp_encode_list_single() {
    let items = vec![vec![0x01]];
    let encoded = rlp_encode_list(&items);
    assert_eq!(encoded, vec![0xc1, 0x01]);
}

#[test]
fn test_transaction_new_transfer() {
    let to = EthAddress([1u8; 20]);
    let tx = Transaction::new_transfer(to, 1000, 0, 20_000_000_000, 1);

    assert_eq!(tx.nonce, 0);
    assert_eq!(tx.value, 1000);
    assert_eq!(tx.gas_limit, 21000);
    assert_eq!(tx.chain_id, 1);
    assert!(tx.data.is_empty());
}

#[test]
fn test_transaction_erc20_transfer_data() {
    let token = EthAddress([2u8; 20]);
    let to = EthAddress([3u8; 20]);
    let tx = Transaction::new_erc20_transfer(token, to, 100, 0, 20_000_000_000, 1);

    assert_eq!(&tx.data[0..4], &[0xa9, 0x05, 0x9c, 0xbb]);
    assert_eq!(tx.data.len(), 68);
    assert_eq!(tx.gas_limit, 65000);
    assert_eq!(tx.value, 0);
}

#[test]
fn test_transaction_nox_transfer() {
    let to = EthAddress([4u8; 20]);
    let tx = Transaction::new_nox_transfer(to, 500, 1, 10_000_000_000, 1);

    assert_eq!(tx.to.as_ref().unwrap().0, NOX_TOKEN_ADDRESS);
    assert_eq!(&tx.data[0..4], &[0xa9, 0x05, 0x9c, 0xbb]);
}

#[test]
fn test_transaction_signing_hash_deterministic() {
    let to = EthAddress([1u8; 20]);
    let tx = Transaction::new_transfer(to, 0, 0, 0, 1);

    let hash1 = tx.signing_hash();
    let hash2 = tx.signing_hash();
    assert_eq!(hash1, hash2);
}

#[test]
fn test_trim_leading_zeros() {
    assert_eq!(trim_leading_zeros(&[0, 0, 1, 2]), &[1, 2]);
    assert_eq!(trim_leading_zeros(&[0, 0, 0]), &[0]);
    assert_eq!(trim_leading_zeros(&[1, 2, 3]), &[1, 2, 3]);
}

#[test]
fn test_parse_wei_integer() {
    let wei = parse_wei("1").unwrap();
    assert_eq!(wei, 1_000_000_000_000_000_000);
}

#[test]
fn test_parse_wei_decimal() {
    let wei = parse_wei("0.5").unwrap();
    assert_eq!(wei, 500_000_000_000_000_000);
}

#[test]
fn test_parse_wei_small() {
    let wei = parse_wei("0.000000000000000001").unwrap();
    assert_eq!(wei, 1);
}

#[test]
fn test_parse_wei_zero() {
    let wei = parse_wei("0").unwrap();
    assert_eq!(wei, 0);
}

#[test]
fn test_parse_wei_invalid() {
    assert!(parse_wei("abc").is_none());
    assert!(parse_wei("1.2.3").is_none());
}

#[test]
fn test_wei_to_gwei() {
    assert_eq!(wei_to_gwei(1_000_000_000), 1);
    assert_eq!(wei_to_gwei(20_000_000_000), 20);
}

#[test]
fn test_gwei_to_wei() {
    assert_eq!(gwei_to_wei(1), 1_000_000_000);
    assert_eq!(gwei_to_wei(20), 20_000_000_000);
}

#[test]
fn test_gwei_wei_roundtrip() {
    let gwei = 42;
    let wei = gwei_to_wei(gwei);
    let back = wei_to_gwei(wei);
    assert_eq!(back, gwei);
}

#[test]
fn test_eth_sign_message_prefix() {
    let msg = b"hello";
    let hash = eth_sign_message(msg);

    assert_eq!(hash.len(), 32);

    let hash2 = eth_sign_message(msg);
    assert_eq!(hash, hash2);
}

#[test]
fn test_eth_sign_message_different_inputs() {
    let hash1 = eth_sign_message(b"hello");
    let hash2 = eth_sign_message(b"world");
    assert_ne!(hash1, hash2);
}

#[test]
fn test_rlp_encode_length_small() {
    assert_eq!(rlp_encode_length(100), vec![100]);
}

#[test]
fn test_rlp_encode_length_medium() {
    assert_eq!(rlp_encode_length(256), vec![0x01, 0x00]);
}

#[test]
fn test_rlp_encode_length_large() {
    assert_eq!(rlp_encode_length(65536), vec![0x01, 0x00, 0x00]);
}

#[test]
fn test_signed_transaction_to_hex_prefix() {
    let tx = Transaction::new_transfer(EthAddress([0u8; 20]), 0, 0, 0, 1);
    let signed = SignedTransaction {
        tx,
        v: 37,
        r: [0u8; 32],
        s: [0u8; 32],
    };

    let hex = signed.to_hex();
    assert_eq!(&hex[0..2], b"0x");
    for &c in &hex[2..] {
        assert!(b"0123456789abcdef".contains(&c));
    }
}
