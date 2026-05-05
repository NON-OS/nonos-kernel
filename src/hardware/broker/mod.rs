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

mod claim;
mod class;
mod device;
mod table;

pub use claim::{
    claim as claim_device, lookup as claim_lookup, release as release_device,
    release_all_for_pid, Claim, ClaimError,
};
pub use class::{classify_pci, Class};
pub use device::{Bar, BarKind, BusKind, DeviceRecord, DEVICE_FLAG_CLAIMED, DEVICE_FLAG_DISABLED};
pub use table::{contains, init_from_pci, list, list_by_class};
