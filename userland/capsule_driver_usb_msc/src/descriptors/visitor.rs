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
use crate::protocol::MAX_BINDINGS;

pub(super) fn visit_record(rec: &[u8], cur: &mut Option<MscBinding>, out: &mut ProbeResult) {
    match rec[1] {
        DESC_INTERFACE => visit_interface(rec, cur),
        DESC_ENDPOINT => visit_endpoint(rec, cur, out),
        _ => {}
    }
}

fn visit_interface(rec: &[u8], cur: &mut Option<MscBinding>) {
    if rec.len() < 9 {
        *cur = None;
        return;
    }
    let is_msc = rec[5] == CLASS_MASS_STORAGE
        && rec[6] == SUBCLASS_SCSI_TRANSPARENT
        && rec[7] == PROTOCOL_BULK_ONLY;
    *cur = is_msc.then_some(MscBinding { interface: rec[2], ..MscBinding::default() });
}

fn visit_endpoint(rec: &[u8], cur: &mut Option<MscBinding>, out: &mut ProbeResult) {
    let Some(mut binding) = *cur else { return };
    if rec.len() < 7 || rec[3] & EP_ATTR_TRANSFER_MASK != EP_ATTR_BULK {
        return;
    }
    bind_endpoint(rec, &mut binding);
    *cur = Some(binding);
    if binding.bulk_in != 0 && binding.bulk_out != 0 && out.count < MAX_BINDINGS {
        out.bindings[out.count] = binding;
        out.count += 1;
        *cur = None;
    }
}

fn bind_endpoint(rec: &[u8], binding: &mut MscBinding) {
    let max_packet = u16::from_le_bytes([rec[4], rec[5]]);
    if rec[2] & EP_DIR_IN != 0 {
        binding.bulk_in = rec[2];
        binding.max_packet_in = max_packet;
    } else {
        binding.bulk_out = rec[2];
        binding.max_packet_out = max_packet;
    }
}
