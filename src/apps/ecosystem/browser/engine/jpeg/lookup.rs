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

use super::huffman::HuffmanTable;
use super::markers::{HuffmanTableData, QuantTable};

pub(super) fn find_huffman_table(
    tables: &[HuffmanTableData],
    class: u8,
    id: u8,
) -> Option<HuffmanTable> {
    tables.iter().find(|t| t.class == class && t.id == id).and_then(|t| HuffmanTable::from_dht(t))
}

pub(super) fn find_quant_table(tables: &[QuantTable], id: u8) -> Option<[u16; 64]> {
    tables.iter().find(|t| t.id == id).map(|t| t.values)
}
