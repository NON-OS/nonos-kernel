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

use crate::bot::CommandStatus;
use crate::descriptors::{MscBinding, ProbeResult};
use crate::protocol::MAX_BINDINGS;

pub struct State {
    bindings: [MscBinding; MAX_BINDINGS],
    binding_count: usize,
    next_tag: u32,
    last_tag: u32,
    probes: u64,
    csw_ok: u64,
    csw_failed: u64,
    phase_errors: u64,
    residue_bytes: u64,
}

impl State {
    pub fn new() -> Self {
        Self {
            bindings: [MscBinding::default(); MAX_BINDINGS],
            binding_count: 0,
            next_tag: 1,
            last_tag: 0,
            probes: 0,
            csw_ok: 0,
            csw_failed: 0,
            phase_errors: 0,
            residue_bytes: 0,
        }
    }

    pub fn install_bindings(&mut self, probe: &ProbeResult) {
        self.bindings = probe.bindings;
        self.binding_count = probe.count;
        self.probes = self.probes.saturating_add(1);
    }

    pub fn next_tag(&mut self) -> u32 {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1).max(1);
        self.last_tag = tag;
        tag
    }

    pub fn accept_csw(&mut self, csw: CommandStatus) {
        if csw.tag != self.last_tag {
            self.phase_errors = self.phase_errors.saturating_add(1);
        }
        self.residue_bytes = self.residue_bytes.saturating_add(csw.residue as u64);
        match csw.status {
            0 => self.csw_ok = self.csw_ok.saturating_add(1),
            1 => self.csw_failed = self.csw_failed.saturating_add(1),
            _ => self.phase_errors = self.phase_errors.saturating_add(1),
        }
    }

    pub fn write_snapshot(&self, out: &mut [u8]) -> usize {
        out[0..8].copy_from_slice(&self.probes.to_le_bytes());
        out[8..16].copy_from_slice(&self.csw_ok.to_le_bytes());
        out[16..24].copy_from_slice(&self.csw_failed.to_le_bytes());
        out[24..32].copy_from_slice(&self.phase_errors.to_le_bytes());
        out[32..36].copy_from_slice(&(self.binding_count as u32).to_le_bytes());
        out[36..44].copy_from_slice(&self.residue_bytes.to_le_bytes());
        out[44..48].copy_from_slice(&self.last_tag.to_le_bytes());
        48
    }
}
