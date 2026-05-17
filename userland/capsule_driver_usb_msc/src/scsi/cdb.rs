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

pub fn inquiry() -> ([u8; 16], u8) {
    let mut cdb = [0u8; 16];
    cdb[0] = 0x12;
    cdb[4] = 36;
    (cdb, 6)
}

pub fn read_capacity10() -> ([u8; 16], u8) {
    let mut cdb = [0u8; 16];
    cdb[0] = 0x25;
    (cdb, 10)
}

pub fn read10(lba: u32, blocks: u16) -> ([u8; 16], u8) {
    block_cdb(0x28, lba, blocks)
}

pub fn write10(lba: u32, blocks: u16) -> ([u8; 16], u8) {
    block_cdb(0x2A, lba, blocks)
}

fn block_cdb(op: u8, lba: u32, blocks: u16) -> ([u8; 16], u8) {
    let mut cdb = [0u8; 16];
    cdb[0] = op;
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[7..9].copy_from_slice(&blocks.to_be_bytes());
    (cdb, 10)
}
