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

pub mod constants;
pub mod error;
pub mod state;
pub mod mmio;
pub mod init;
pub mod ops;
pub mod ipi;
pub mod timer;

pub use constants::{VEC_SPURIOUS, VEC_TIMER, VEC_THERMAL, VEC_ERROR};
pub use error::{ApicError, ApicResult};
pub use state::{has_xapic, has_x2apic, has_tsc_deadline, is_initialized, is_x2apic, supports_tsc_deadline};
pub use init::{init, init_apic};
pub use ops::{id, set_tpr, get_tpr, eoi, send_eoi, version, max_lvt, status, ApicStatus};
pub use ipi::{ipi_self, ipi_one, ipi_all, ipi_others, start_ap};
pub use timer::{TimerMode, timer_enable, timer_oneshot, timer_deadline_tsc, timer_mask, timer_unmask, timer_current, divider_to_code, calibrate_timer};
