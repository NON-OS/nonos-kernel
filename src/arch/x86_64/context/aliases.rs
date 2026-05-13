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

// On x86_64 the live first-entry record IS the iretq 5-tuple; the
// preempt snapshot IS the 15-GPR-plus-iretq capture. Both types
// already exist in the userspace module; alias them here so the
// arch-neutral `arch::context::{UserEntry, SavedUser}` resolves to
// the same in-memory shape on x86 with no field renames.
pub use crate::process::userspace::types::InterruptFrame as UserEntry;
pub use crate::process::userspace::types::UserContext as SavedUser;
