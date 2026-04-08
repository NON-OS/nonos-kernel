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

pub mod log;
pub mod panic;
mod main;
mod main_start;
mod main_early;
mod main_late;
mod main_cpu;
#[cfg(test)]
mod tests;

pub use panic::boot_panic;
#[cfg(not(feature = "std"))]
pub use main::_arch_start;
pub use main::boot_main;
