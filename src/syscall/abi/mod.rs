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

mod domain;
mod entry;
mod registry;
mod status;
mod tag;

pub use domain::AbiDomain;
pub use entry::AbiEntry;
pub use registry::REGISTRY;
pub use status::AbiStatus;
pub use tag::tag4;

use crate::syscall::numbers::SyscallNumber;

pub fn lookup_id(id: u64) -> Option<SyscallNumber> {
    for slice in REGISTRY {
        for entry in *slice {
            if entry.id == id {
                return Some(entry.variant);
            }
        }
    }
    None
}

pub fn lookup_name(id: u64) -> Option<&'static str> {
    for slice in REGISTRY {
        for entry in *slice {
            if entry.id == id {
                return Some(entry.name);
            }
        }
    }
    None
}
