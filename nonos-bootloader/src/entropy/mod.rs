// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

mod collector;
mod getrandom;
mod sources;
mod types;
mod util;

pub use types::{
    DS_ENTROPY_ACCUM, DS_ENTROPY_OUTPUT, ENTROPY_POOL_SIZE, HW_RNG_ITERATIONS, TSC_JITTER_ROUNDS,
};

pub use collector::{
    collect_boot_entropy, collect_boot_entropy_64, get_rtc_timestamp, seed_entropy,
};

pub use getrandom::getrandom;

pub use sources::{rdrand64, rdseed64, rdtsc_serialized};

pub use util::{is_weak_entropy, scrub};
