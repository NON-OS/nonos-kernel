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

pub mod asm;
pub mod calibration;
pub mod constants;
mod conversion;
pub mod cpuid_ops;
mod deadline;
mod delay;
mod elapsed;
mod error;
mod features;
pub mod globals;
mod init_state;
pub mod io;
mod per_cpu;
mod rdtsc;
pub mod state;
mod stats_query;
pub mod types;

pub use error::{TscError, TscResult};
pub use types::{TscFeatures, CalibrationSource, TscStatistics, TscCalibration, PerCpuTsc};
pub use asm::{rdtsc, rdtsc_unserialized, rdtscp, read_tsc, read_tsc_cpu, tsc_fence};
pub use features::{detect_features, is_tsc_available, is_invariant, has_rdtscp, has_deadline_mode, get_features};
pub use calibration::{calibrate, calibrate_with_hpet_base, set_frequency, get_frequency, get_frequency_mhz};
pub use calibration::cpuid::get_cpuid_frequency;
pub use calibration::pit::calibrate_with_pit;
pub use calibration::hpet::calibrate_with_hpet;
pub use conversion::{ticks_to_ns, ticks_to_us, ticks_to_ms, ns_to_ticks, us_to_ticks, ms_to_ticks, tsc_to_ns, ns_to_tsc};
pub use elapsed::{elapsed_ns, elapsed_us, elapsed_ms, elapsed_secs};
pub use delay::{delay_ns, delay_us, delay_ms, delay_precise_ns};
pub use per_cpu::{init_cpu, sync_with_bsp, get_cpu_offset, read_synchronized};
pub use deadline::{write_deadline, read_deadline, set_deadline_ns, clear_deadline};
pub use state::{init, init_with_hpet, is_initialized, is_calibrated, get_statistics, get_calibration_source, get_confidence};
pub use cpuid_ops::{cpuid, cpuid_max_leaf, cpuid_max_extended_leaf};
pub use io::{inb, outb};
pub use globals::{INITIALIZED, CALIBRATED, FEATURES, CALIBRATION, PER_CPU_TSC, STATS_RDTSC_CALLS, STATS_RDTSCP_CALLS};
pub use constants::{MAX_CPUS, DEFAULT_CALIBRATION_MS, CALIBRATION_SAMPLES, MIN_FREQUENCY, MAX_FREQUENCY};
