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

use super::dht::parse_dht;
use super::dqt::parse_dqt;
use super::sof::parse_sof;
use super::sos::parse_sos;
use super::types::{HuffmanTableData, JpegMarkers, QuantTable, SofData, SosData};
use super::util::*;
use alloc::vec::Vec;

pub(in crate::apps::ecosystem::browser::engine::jpeg) fn parse_markers(
    data: &[u8],
) -> Option<JpegMarkers> {
    if data.len() < 4 {
        return None;
    }
    if data[0] != 0xFF || data[1] != MARKER_SOI {
        return None;
    }
    let mut pos: usize = 2;
    let mut sof: Option<SofData> = None;
    let mut quant_tables: Vec<QuantTable> = Vec::new();
    let mut huffman_tables: Vec<HuffmanTableData> = Vec::new();
    let mut sos: Option<SosData> = None;
    while pos + 1 < data.len() {
        if data[pos] != 0xFF {
            return None;
        }
        while pos + 1 < data.len() && data[pos + 1] == 0xFF {
            pos += 1;
        }
        if pos + 1 >= data.len() {
            return None;
        }
        let marker = data[pos + 1];
        pos += 2;
        match marker {
            MARKER_EOI => break,
            MARKER_SOI => {}
            0x00 => {}
            0xD0..=0xD7 => {}
            MARKER_SOS => {
                sos = Some(parse_sos(data, pos)?);
                break;
            }
            MARKER_SOF0 => {
                let length = read_u16_be(data, pos)? as usize;
                sof = Some(parse_sof(data, pos, true)?);
                pos += length;
            }
            MARKER_SOF2 => {
                let length = read_u16_be(data, pos)? as usize;
                sof = Some(parse_sof(data, pos, false)?);
                pos += length;
            }
            MARKER_DHT => {
                let length = read_u16_be(data, pos)? as usize;
                if pos + length > data.len() {
                    return None;
                }
                parse_dht(data, pos, length, &mut huffman_tables)?;
                pos += length;
            }
            MARKER_DQT => {
                let length = read_u16_be(data, pos)? as usize;
                if pos + length > data.len() {
                    return None;
                }
                parse_dqt(data, pos, length, &mut quant_tables)?;
                pos += length;
            }
            _ => {
                let length = read_u16_be(data, pos).unwrap_or(0) as usize;
                if length < 2 {
                    return None;
                }
                pos += length;
            }
        }
    }
    Some(JpegMarkers { sof: sof?, quant_tables, huffman_tables, sos: sos? })
}
