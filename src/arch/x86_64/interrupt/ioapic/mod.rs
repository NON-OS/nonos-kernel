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
pub mod types;
pub mod state;
pub mod mmio;
pub mod init;
pub mod ops;

pub use error::{IoApicError, IoApicResult};
pub use types::{Rte, MadtIoApic, MadtIso, MadtNmi, IsoFlags};
pub use state::{is_initialized, count};
pub use init::init;
pub use ops::{claim_gsi_for_msi, release_gsi_from_msi, alloc_route, program_route, mask, retarget, free_vector, query, snapshot, restore, status, IoApicStatus};
