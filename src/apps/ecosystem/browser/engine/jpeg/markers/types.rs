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

use alloc::vec::Vec;

#[derive(Debug, Clone, Copy)]
pub(in crate::apps::ecosystem::browser::engine::jpeg) struct ComponentInfo {
    pub(in crate::apps::ecosystem::browser::engine::jpeg) id: u8,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) h_sampling: u8,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) v_sampling: u8,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) quant_table_id: u8,
}

#[derive(Debug, Clone)]
pub(in crate::apps::ecosystem::browser::engine::jpeg) struct SofData {
    pub(in crate::apps::ecosystem::browser::engine::jpeg) is_baseline: bool,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) _precision: u8,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) width: u32,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) height: u32,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) components: Vec<ComponentInfo>,
}

#[derive(Debug, Clone)]
pub(in crate::apps::ecosystem::browser::engine::jpeg) struct HuffmanTableData {
    pub(in crate::apps::ecosystem::browser::engine::jpeg) class: u8,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) id: u8,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) counts: [u8; 16],
    pub(in crate::apps::ecosystem::browser::engine::jpeg) symbols: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(in crate::apps::ecosystem::browser::engine::jpeg) struct QuantTable {
    pub(in crate::apps::ecosystem::browser::engine::jpeg) id: u8,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) values: [u16; 64],
}

#[derive(Debug, Clone, Copy)]
pub(in crate::apps::ecosystem::browser::engine::jpeg) struct ScanComponent {
    pub(in crate::apps::ecosystem::browser::engine::jpeg) component_id: u8,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) dc_table_id: u8,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) ac_table_id: u8,
}

#[derive(Debug, Clone)]
pub(in crate::apps::ecosystem::browser::engine::jpeg) struct SosData {
    pub(in crate::apps::ecosystem::browser::engine::jpeg) components: Vec<ScanComponent>,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) entropy_data_offset: usize,
}

#[derive(Debug, Clone)]
pub(in crate::apps::ecosystem::browser::engine::jpeg) struct JpegMarkers {
    pub(in crate::apps::ecosystem::browser::engine::jpeg) sof: SofData,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) quant_tables: Vec<QuantTable>,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) huffman_tables: Vec<HuffmanTableData>,
    pub(in crate::apps::ecosystem::browser::engine::jpeg) sos: SosData,
}
