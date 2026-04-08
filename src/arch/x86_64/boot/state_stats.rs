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

use core::sync::atomic::Ordering;

use super::stage::BootStage;
use super::state_globals::*;
use super::types::BootStats;

pub fn get_stats() -> BootStats {
    let mut stage_tsc = [0u64; BootStage::COUNT];
    for i in 0..BootStage::COUNT {
        stage_tsc[i] = STAGE_TSC[i].load(Ordering::Relaxed);
    }

    BootStats {
        stage: BOOT_STAGE.load(Ordering::Relaxed),
        error: BOOT_ERROR.load(Ordering::Relaxed),
        complete: BOOT_COMPLETE.load(Ordering::Relaxed),
        boot_tsc: BOOT_TSC.load(Ordering::Relaxed),
        complete_tsc: stage_tsc[BootStage::Complete.as_u8() as usize],
        exceptions: EXCEPTION_COUNT.load(Ordering::Relaxed),
        stage_tsc,
    }
}
