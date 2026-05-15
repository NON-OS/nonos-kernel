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

use super::types::{MscBinding, ProbeResult};
use super::wire::*;
use crate::protocol::{E_INVAL, E_NO_MSC, MAX_BINDINGS};

pub fn parse_config(raw: &[u8]) -> Result<ProbeResult, i32> {
    if raw.len() < 9 || raw[1] != DESC_CONFIGURATION {
        return Err(E_INVAL);
    }
    let total = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    if total < 9 || total > raw.len() {
        return Err(E_INVAL);
    }
    let mut out = ProbeResult::empty();
    let mut current: Option<MscBinding> = None;
    let mut pos = 0usize;
    while pos + 2 <= total {
        let len = raw[pos] as usize;
        if len < 2 || pos + len > total {
            return Err(E_INVAL);
        }
        visit_record(&raw[pos..pos + len], &mut current, &mut out);
        pos += len;
    }
    if out.count == 0 {
        Err(E_NO_MSC)
    } else {
        Ok(out)
    }
}

fn visit_record(rec: &[u8], current: &mut Option<MscBinding>, out: &mut ProbeResult) {
    match rec[1] {
        DESC_INTERFACE => visit_interface(rec, current),
        DESC_ENDPOINT => visit_endpoint(rec, current, out),
        _ => {}
    }
}

fn visit_interface(rec: &[u8], current: &mut Option<MscBinding>) {
    if rec.len() < 9 {
        *current = None;
        return;
    }
    let is_msc = rec[5] == CLASS_MASS_STORAGE
        && rec[6] == SUBCLASS_SCSI_TRANSPARENT
        && rec[7] == PROTOCOL_BULK_ONLY;
    *current = is_msc.then_some(MscBinding { interface: rec[2], ..MscBinding::default() });
}

fn visit_endpoint(rec: &[u8], current: &mut Option<MscBinding>, out: &mut ProbeResult) {
    let Some(mut binding) = *current else { return };
    if rec.len() < 7 || rec[3] & EP_ATTR_TRANSFER_MASK != EP_ATTR_BULK {
        return;
    }
    let max_packet = u16::from_le_bytes([rec[4], rec[5]]);
    if rec[2] & EP_DIR_IN != 0 {
        binding.bulk_in = rec[2];
        binding.max_packet_in = max_packet;
    } else {
        binding.bulk_out = rec[2];
        binding.max_packet_out = max_packet;
    }
    *current = Some(binding);
    if binding.bulk_in != 0 && binding.bulk_out != 0 && out.count < MAX_BINDINGS {
        out.bindings[out.count] = binding;
        out.count += 1;
        *current = None;
    }
}
