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

// Capsules are spawned once at boot (`userspace::init::entry`) and are
// not restarted from inside the kernel; a dead capsule fails closed
// from its IPC client. The supervisor walks the lifecycle registry
// for liveness only.
pub(super) fn supervise_services() {
    crate::services::lifecycle::tick();
}
