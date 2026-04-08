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

use super::stage::BootStage;

#[derive(Clone, Copy, Default)]
pub struct BootStats {
    pub stage: u8,
    pub error: u8,
    pub complete: bool,
    pub boot_tsc: u64,
    pub complete_tsc: u64,
    pub exceptions: u64,
    pub stage_tsc: [u64; BootStage::COUNT],
}

impl BootStats {
    pub fn duration_tsc(&self) -> u64 {
        if self.complete_tsc > self.boot_tsc { self.complete_tsc - self.boot_tsc } else { 0 }
    }
    pub fn stage_duration(&self, stage: BootStage) -> u64 {
        let idx = stage.as_u8() as usize;
        if idx == 0 || idx >= BootStage::COUNT { return 0; }
        let (current, prev) = (self.stage_tsc[idx], self.stage_tsc[idx - 1]);
        if current > prev { current - prev } else { 0 }
    }
    pub fn current_stage(&self) -> BootStage { BootStage::from_u8(self.stage) }
    pub fn is_complete(&self) -> bool { self.complete }
    pub fn has_error(&self) -> bool { self.error != 0 }
}

impl core::fmt::Debug for BootStats {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BootStats")
            .field("stage", &BootStage::from_u8(self.stage))
            .field("error", &self.error).field("complete", &self.complete)
            .field("duration_tsc", &self.duration_tsc()).field("exceptions", &self.exceptions)
            .finish()
    }
}
