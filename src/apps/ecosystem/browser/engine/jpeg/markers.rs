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

use alloc::vec::Vec;

/// Maximum image dimension (consistent with PNG decoder).
const MAX_DIMENSION: u32 = 4096;

// JPEG marker bytes (second byte after 0xFF)
const MARKER_SOI: u8 = 0xD8;
const MARKER_SOF0: u8 = 0xC0; // Baseline DCT
const MARKER_SOF2: u8 = 0xC2; // Progressive DCT
const MARKER_DHT: u8 = 0xC4;
const MARKER_DQT: u8 = 0xDB;
const MARKER_SOS: u8 = 0xDA;
const MARKER_EOI: u8 = 0xD9;

/// Frame component info from SOF marker.
#[derive(Debug, Clone, Copy)]
pub struct ComponentInfo {
    pub id: u8,
    pub h_sampling: u8,
    pub v_sampling: u8,
    pub quant_table_id: u8,
}

/// Start of Frame data.
#[derive(Debug, Clone)]
pub struct SofData {
    pub is_baseline: bool,
    pub precision: u8,
    pub width: u32,
    pub height: u32,
    pub components: Vec<ComponentInfo>,
}

/// A single Huffman table extracted from DHT.
#[derive(Debug, Clone)]
pub struct HuffmanTableData {
    pub class: u8, // 0 = DC, 1 = AC
    pub id: u8,    // table destination (0-3)
    pub counts: [u8; 16],
    pub symbols: Vec<u8>,
}

/// A single quantization table extracted from DQT.
#[derive(Debug, Clone)]
pub struct QuantTable {
    pub id: u8,
    pub values: [u16; 64],
}

/// Scan header component reference.
#[derive(Debug, Clone, Copy)]
pub struct ScanComponent {
    pub component_id: u8,
    pub dc_table_id: u8,
    pub ac_table_id: u8,
}

/// Start of Scan data.
#[derive(Debug, Clone)]
pub struct SosData {
    pub components: Vec<ScanComponent>,
    pub entropy_data_offset: usize,
}

/// All parsed marker data from a JPEG file.
#[derive(Debug, Clone)]
pub struct JpegMarkers {
    pub sof: SofData,
    pub quant_tables: Vec<QuantTable>,
    pub huffman_tables: Vec<HuffmanTableData>,
    pub sos: SosData,
}

fn read_u16_be(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() { return None; }
    Some(((data[offset] as u16) << 8) | (data[offset + 1] as u16))
}

/// Parse all JPEG markers from raw data. Returns `None` for unsupported or
/// corrupt files.
pub fn parse_markers(data: &[u8]) -> Option<JpegMarkers> {
    if data.len() < 4 { return None; }
    // Verify SOI
    if data[0] != 0xFF || data[1] != MARKER_SOI { return None; }

    let mut pos: usize = 2;
    let mut sof: Option<SofData> = None;
    let mut quant_tables: Vec<QuantTable> = Vec::new();
    let mut huffman_tables: Vec<HuffmanTableData> = Vec::new();
    let mut sos: Option<SosData> = None;

    while pos + 1 < data.len() {
        // Find 0xFF marker prefix
        if data[pos] != 0xFF { return None; }
        // Skip any fill bytes (0xFF 0xFF ...)
        while pos + 1 < data.len() && data[pos + 1] == 0xFF {
            pos += 1;
        }
        if pos + 1 >= data.len() { return None; }
        let marker = data[pos + 1];
        pos += 2;

        match marker {
            MARKER_EOI => break,
            MARKER_SOI => { /* ignore duplicate SOI */ }
            0x00 => { /* byte-stuffed 0xFF00 — should not appear outside entropy data */ }
            // Restart markers (RST0-RST7) are standalone
            0xD0..=0xD7 => {}
            MARKER_SOS => {
                sos = Some(parse_sos(data, pos)?);
                break; // Entropy data follows SOS directly
            }
            MARKER_SOF0 => {
                let length = read_u16_be(data, pos)? as usize;
                sof = Some(parse_sof(data, pos, true)?);
                pos += length;
            }
            MARKER_SOF2 => {
                // Progressive — we parse it but flag it as non-baseline
                let length = read_u16_be(data, pos)? as usize;
                sof = Some(parse_sof(data, pos, false)?);
                pos += length;
            }
            MARKER_DHT => {
                let length = read_u16_be(data, pos)? as usize;
                if pos + length > data.len() { return None; }
                parse_dht(data, pos, length, &mut huffman_tables)?;
                pos += length;
            }
            MARKER_DQT => {
                let length = read_u16_be(data, pos)? as usize;
                if pos + length > data.len() { return None; }
                parse_dqt(data, pos, length, &mut quant_tables)?;
                pos += length;
            }
            _ => {
                // Skip unknown marker segment
                let length = read_u16_be(data, pos).unwrap_or(0) as usize;
                if length < 2 { return None; }
                pos += length;
            }
        }
    }

    Some(JpegMarkers {
        sof: sof?,
        quant_tables,
        huffman_tables,
        sos: sos?,
    })
}

fn parse_sof(data: &[u8], pos: usize, is_baseline: bool) -> Option<SofData> {
    // Length(2) + Precision(1) + Height(2) + Width(2) + Nf(1) = 8 min
    let length = read_u16_be(data, pos)? as usize;
    if length < 8 || pos + length > data.len() { return None; }
    let precision = data[pos + 2];
    let height = read_u16_be(data, pos + 3)? as u32;
    let width = read_u16_be(data, pos + 5)? as u32;
    let num_components = data[pos + 7] as usize;

    if width == 0 || height == 0 { return None; }
    if width > MAX_DIMENSION || height > MAX_DIMENSION { return None; }
    if num_components == 0 || num_components > 4 { return None; }
    if length < 8 + num_components * 3 { return None; }

    let mut components = Vec::with_capacity(num_components);
    for i in 0..num_components {
        let offset = pos + 8 + i * 3;
        let id = data[offset];
        let sampling = data[offset + 1];
        let h_sampling = sampling >> 4;
        let v_sampling = sampling & 0x0F;
        let quant_table_id = data[offset + 2];
        if h_sampling == 0 || v_sampling == 0 || h_sampling > 4 || v_sampling > 4 { return None; }
        components.push(ComponentInfo { id, h_sampling, v_sampling, quant_table_id });
    }

    Some(SofData { is_baseline, precision, width, height, components })
}

fn parse_dht(
    data: &[u8],
    pos: usize,
    length: usize,
    tables: &mut Vec<HuffmanTableData>,
) -> Option<()> {
    let end = pos + length;
    let mut cur = pos + 2; // skip length field
    while cur < end {
        if cur >= data.len() { return None; }
        let info = data[cur];
        let class = (info >> 4) & 0x0F;
        let id = info & 0x0F;
        if class > 1 || id > 3 { return None; }
        cur += 1;
        if cur + 16 > data.len() { return None; }
        let mut counts = [0u8; 16];
        let mut total: usize = 0;
        for i in 0..16 {
            counts[i] = data[cur + i];
            total += counts[i] as usize;
        }
        cur += 16;
        if cur + total > data.len() { return None; }
        let symbols = data[cur..cur + total].to_vec();
        cur += total;
        tables.push(HuffmanTableData { class, id, counts, symbols });
    }
    Some(())
}

fn parse_dqt(
    data: &[u8],
    pos: usize,
    length: usize,
    tables: &mut Vec<QuantTable>,
) -> Option<()> {
    let end = pos + length;
    let mut cur = pos + 2; // skip length field
    while cur < end {
        if cur >= data.len() { return None; }
        let info = data[cur];
        let precision = (info >> 4) & 0x0F; // 0 = 8-bit, 1 = 16-bit
        let id = info & 0x0F;
        if id > 3 { return None; }
        cur += 1;
        let mut values = [0u16; 64];
        if precision == 0 {
            if cur + 64 > data.len() { return None; }
            for i in 0..64 {
                values[i] = data[cur + i] as u16;
            }
            cur += 64;
        } else {
            if cur + 128 > data.len() { return None; }
            for i in 0..64 {
                values[i] = read_u16_be(data, cur + i * 2)?;
            }
            cur += 128;
        }
        tables.push(QuantTable { id, values });
    }
    Some(())
}

fn parse_sos(data: &[u8], pos: usize) -> Option<SosData> {
    let length = read_u16_be(data, pos)? as usize;
    if length < 3 || pos + length > data.len() { return None; }
    let num_components = data[pos + 2] as usize;
    if num_components == 0 || num_components > 4 { return None; }
    if length < 3 + num_components * 2 + 3 { return None; }

    let mut components = Vec::with_capacity(num_components);
    for i in 0..num_components {
        let offset = pos + 3 + i * 2;
        let component_id = data[offset];
        let table_sel = data[offset + 1];
        let dc_table_id = (table_sel >> 4) & 0x0F;
        let ac_table_id = table_sel & 0x0F;
        components.push(ScanComponent { component_id, dc_table_id, ac_table_id });
    }

    let entropy_data_offset = pos + length;
    Some(SosData { components, entropy_data_offset })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid baseline JPEG with one 8×8 MCU.
    /// This is the smallest possible valid JPEG: single-component grayscale.
    fn build_minimal_jpeg() -> Vec<u8> {
        let mut data = Vec::new();
        // SOI
        data.extend_from_slice(&[0xFF, 0xD8]);

        // DQT — all-ones quantization table (id=0, 8-bit)
        let dqt_len: u16 = 2 + 1 + 64; // length + info + 64 values
        data.extend_from_slice(&[0xFF, 0xDB]);
        data.extend_from_slice(&dqt_len.to_be_bytes());
        data.push(0x00); // precision=0 (8-bit), id=0
        for _ in 0..64 { data.push(1); }

        // SOF0 — baseline, 8×8 grayscale (1 component)
        let sof_len: u16 = 2 + 1 + 2 + 2 + 1 + 3; // = 11
        data.extend_from_slice(&[0xFF, 0xC0]);
        data.extend_from_slice(&sof_len.to_be_bytes());
        data.push(8);    // precision
        data.extend_from_slice(&8u16.to_be_bytes()); // height
        data.extend_from_slice(&8u16.to_be_bytes()); // width
        data.push(1);    // 1 component
        data.push(1);    // component id
        data.push(0x11); // h_sampling=1, v_sampling=1
        data.push(0);    // quant table id 0

        // DHT — DC table (class=0, id=0): one symbol (value 0) with code length 1
        let dht_dc_len: u16 = 2 + 1 + 16 + 1;
        data.extend_from_slice(&[0xFF, 0xC4]);
        data.extend_from_slice(&dht_dc_len.to_be_bytes());
        data.push(0x00); // class=0 (DC), id=0
        // Counts: 1 code of length 1, rest zero
        data.push(1);
        for _ in 1..16 { data.push(0); }
        data.push(0x00); // symbol 0 (DC diff = 0 means value 0)

        // DHT — AC table (class=1, id=0): one symbol (EOB = 0x00) with code length 1
        let dht_ac_len: u16 = 2 + 1 + 16 + 1;
        data.extend_from_slice(&[0xFF, 0xC4]);
        data.extend_from_slice(&dht_ac_len.to_be_bytes());
        data.push(0x10); // class=1 (AC), id=0
        data.push(1);
        for _ in 1..16 { data.push(0); }
        data.push(0x00); // symbol 0x00 = EOB

        // SOS — 1 component
        let sos_len: u16 = 2 + 1 + 2 + 3; // = 8
        data.extend_from_slice(&[0xFF, 0xDA]);
        data.extend_from_slice(&sos_len.to_be_bytes());
        data.push(1);    // 1 component
        data.push(1);    // component id
        data.push(0x00); // DC table 0, AC table 0
        data.push(0);    // Ss
        data.push(63);   // Se
        data.push(0);    // Ah/Al

        // Entropy data: DC=0 (code '0' bit), AC=EOB (code '0' bit) = 0b00... pad
        data.push(0x00); // two zero bits then zeros
        data.push(0x00);

        // EOI
        data.extend_from_slice(&[0xFF, 0xD9]);

        data
    }

    #[test]
    fn test_parse_minimal_jpeg() {
        let data = build_minimal_jpeg();
        let markers = parse_markers(&data);
        assert!(markers.is_some());
        let m = markers.unwrap();
        assert!(m.sof.is_baseline);
        assert_eq!(m.sof.width, 8);
        assert_eq!(m.sof.height, 8);
        assert_eq!(m.sof.components.len(), 1);
        assert_eq!(m.quant_tables.len(), 1);
        assert_eq!(m.huffman_tables.len(), 2);
    }

    #[test]
    fn test_reject_too_short() {
        assert!(parse_markers(&[]).is_none());
        assert!(parse_markers(&[0xFF]).is_none());
        assert!(parse_markers(&[0xFF, 0xD8]).is_none());
    }

    #[test]
    fn test_reject_bad_magic() {
        assert!(parse_markers(&[0x00, 0x00, 0x00, 0x00]).is_none());
    }

    #[test]
    fn test_reject_oversized() {
        // Build a JPEG with dimensions exceeding MAX_DIMENSION
        let mut data = Vec::new();
        data.extend_from_slice(&[0xFF, 0xD8]);
        // SOF0 with 8192×8192
        let sof_len: u16 = 11;
        data.extend_from_slice(&[0xFF, 0xC0]);
        data.extend_from_slice(&sof_len.to_be_bytes());
        data.push(8);
        data.extend_from_slice(&8192u16.to_be_bytes()); // height > 4096
        data.extend_from_slice(&8192u16.to_be_bytes()); // width > 4096
        data.push(1);
        data.push(1);
        data.push(0x11);
        data.push(0);
        data.extend_from_slice(&[0xFF, 0xD9]);
        assert!(parse_markers(&data).is_none());
    }

    #[test]
    fn test_parse_3_component_sof() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xFF, 0xD8]);
        // DQT (id 0)
        data.extend_from_slice(&[0xFF, 0xDB]);
        data.extend_from_slice(&67u16.to_be_bytes());
        data.push(0x00);
        for _ in 0..64 { data.push(1); }
        // SOF0 — 16×16 YCbCr 4:2:0
        let sof_len: u16 = 2 + 1 + 2 + 2 + 1 + 9; // 17
        data.extend_from_slice(&[0xFF, 0xC0]);
        data.extend_from_slice(&sof_len.to_be_bytes());
        data.push(8);
        data.extend_from_slice(&16u16.to_be_bytes());
        data.extend_from_slice(&16u16.to_be_bytes());
        data.push(3); // 3 components
        // Y: h=2, v=2
        data.push(1); data.push(0x22); data.push(0);
        // Cb: h=1, v=1
        data.push(2); data.push(0x11); data.push(0);
        // Cr: h=1, v=1
        data.push(3); data.push(0x11); data.push(0);
        // DHT + SOS + EOI (minimal)
        data.extend_from_slice(&[0xFF, 0xC4]);
        data.extend_from_slice(&20u16.to_be_bytes());
        data.push(0x00);
        data.push(1); for _ in 1..16 { data.push(0); }
        data.push(0x00);
        data.extend_from_slice(&[0xFF, 0xC4]);
        data.extend_from_slice(&20u16.to_be_bytes());
        data.push(0x10);
        data.push(1); for _ in 1..16 { data.push(0); }
        data.push(0x00);
        let sos_len: u16 = 2 + 1 + 6 + 3; // 12
        data.extend_from_slice(&[0xFF, 0xDA]);
        data.extend_from_slice(&sos_len.to_be_bytes());
        data.push(3);
        data.push(1); data.push(0x00);
        data.push(2); data.push(0x00);
        data.push(3); data.push(0x00);
        data.push(0); data.push(63); data.push(0);
        data.push(0x00); data.push(0x00);
        data.extend_from_slice(&[0xFF, 0xD9]);

        let markers = parse_markers(&data).unwrap();
        assert_eq!(markers.sof.components.len(), 3);
        assert_eq!(markers.sof.components[0].h_sampling, 2);
        assert_eq!(markers.sof.components[0].v_sampling, 2);
        assert_eq!(markers.sof.components[1].h_sampling, 1);
        assert_eq!(markers.sof.width, 16);
        assert_eq!(markers.sof.height, 16);
    }
}
