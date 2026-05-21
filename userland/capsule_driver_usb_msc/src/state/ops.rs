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
use crate::descriptors::ProbeResult;

use super::types::State;

impl State {
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
}
