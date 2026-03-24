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

pub const NOX_MAINNET: [u8; 20] = hex_addr("0a26c80Be4E060e688d7C23aDdB92cBb5D2C9eCA");
pub const ZSP_MAINNET: [u8; 20] = hex_addr("7b575DD8e8b111c52Ab1e872924d4Efd4DF403df");
pub const STAKING_MAINNET: [u8; 20] = hex_addr("a94d6009790ba13597a1e1b7cf4e1531ea513613");
pub const FAUCET_SEPOLIA: [u8; 20] = hex_addr("a7a19e50246D191Eeaf5A6A70e3CAf06fB4Df9d7");

pub const YEAR_1_EMISSION: u128 = 28_000_000 * 1_000_000_000_000_000_000;
pub const YEAR_2_EMISSION: u128 = 12_000_000 * 1_000_000_000_000_000_000;
pub const TOTAL_REWARDS: u128 = 40_000_000 * 1_000_000_000_000_000_000;
pub const EPOCH_DURATION: u64 = 7 * 24 * 60 * 60;
pub const GENESIS_TIME: u64 = 1774362336;
pub const MIN_STAKE: u128 = 100 * 1_000_000_000_000_000_000;

pub const BOOST_0_NFT: u32 = 10000;
pub const BOOST_1_NFT: u32 = 15000;
pub const BOOST_2_NFT: u32 = 20000;
pub const BOOST_3_NFT: u32 = 25000;

pub const SIG_STAKE: [u8; 4] = [0xa6, 0x94, 0xfc, 0x3a];
pub const SIG_UNSTAKE: [u8; 4] = [0x2e, 0x17, 0xde, 0x78];
pub const SIG_GET_STAKER_INFO: [u8; 4] = [0x9f, 0xd4, 0xda, 0x40];
pub const SIG_GET_POOL_STATS: [u8; 4] = [0xd4, 0xca, 0xdf, 0x68];
pub const SIG_CLAIM: [u8; 4] = [0x37, 0x93, 0x07, 0xf1];
pub const SIG_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
pub const SIG_BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
pub const SIG_ALLOWANCE: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e];
pub const SIG_REFRESH_BOOST: [u8; 4] = [0x8d, 0x93, 0x02, 0x08];
pub const SIG_PENDING_REWARDS: [u8; 4] = [0x31, 0xa7, 0xbc, 0x41];
pub const SIG_GET_EMISSION_RATE: [u8; 4] = [0x67, 0x96, 0x8f, 0xc5];

const fn hex_addr(s: &str) -> [u8; 20] {
    let b = s.as_bytes(); let mut r = [0u8; 20]; let mut i = 0;
    while i < 20 { r[i] = hex_byte(b[i * 2], b[i * 2 + 1]); i += 1; }
    r
}

const fn hex_byte(h: u8, l: u8) -> u8 { (hex_nibble(h) << 4) | hex_nibble(l) }

const fn hex_nibble(c: u8) -> u8 {
    match c { b'0'..=b'9' => c - b'0', b'a'..=b'f' => c - b'a' + 10, b'A'..=b'F' => c - b'A' + 10, _ => 0 }
}
