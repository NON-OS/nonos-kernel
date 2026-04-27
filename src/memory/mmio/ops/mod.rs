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

mod read_direct;
mod read_validated;
mod write_direct;
mod write_validated;

pub use read_direct::{mmio_r16, mmio_r32, mmio_r64, mmio_r8};
pub(super) use read_validated::{read16_at, read32_at, read64_at, read8_at};
pub use write_direct::{mmio_w16, mmio_w32, mmio_w64, mmio_w8};
pub(super) use write_validated::{write16_at, write32_at, write64_at, write8_at};
