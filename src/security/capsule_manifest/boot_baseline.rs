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

use alloc::collections::BTreeMap;
use spin::Once;

#[derive(Clone, Copy)]
pub struct BaselineHashes {
    pub elf: [u8; 32],
    pub cert: [u8; 32],
    pub manifest: [u8; 32],
}

static BOOT_BASELINE: Once<BTreeMap<&'static str, BaselineHashes>> = Once::new();

pub fn lookup(name: &str) -> Option<BaselineHashes> {
    BOOT_BASELINE.get().and_then(|m| m.get(name).copied())
}

pub fn init_boot_baseline() {
    blake3_self_test();
    let mut map: BTreeMap<&'static str, BaselineHashes> = BTreeMap::new();
    insert_all(&mut map);
    BOOT_BASELINE.call_once(|| map);
    let count = BOOT_BASELINE.get().map(|m| m.len()).unwrap_or(0);
    crate::sys::boot_log::info(&alloc::format!(
        "[boot_baseline] baked {} verified capsules",
        count,
    ));
}

fn blake3_self_test() {
    let input = [0xAAu8; 1024];
    let got = *blake3::hash(&input).as_bytes();
    let expect: [u8; 32] = [
        0x1d, 0x6a, 0xdb, 0x86, 0xdb, 0xe5, 0x98, 0x90,
        0x37, 0x2b, 0x1a, 0xe6, 0x2d, 0xbc, 0xda, 0x91,
        0x0f, 0x5c, 0x98, 0xa1, 0x71, 0x65, 0x98, 0x6e,
        0x51, 0x7d, 0x24, 0x10, 0x87, 0x2f, 0xd4, 0x35,
    ];
    if got != expect {
        panic!(
            "[boot_baseline] blake3 self-test FAILED: got {:02x?} expected {:02x?}",
            got, expect,
        );
    }
}

fn insert_all(_map: &mut BTreeMap<&'static str, BaselineHashes>) {
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}
