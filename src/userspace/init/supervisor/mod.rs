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

#[cfg(feature = "nonos-legacy-tree")]
mod loop_impl;
#[cfg(feature = "nonos-legacy-tree")]
mod supervision;
#[cfg(feature = "nonos-legacy-tree")]
mod verification;

#[cfg(feature = "nonos-legacy-tree")]
pub(crate) use loop_impl::init_loop;

// Microkernel `init_loop`. Real userland capsules own their own
// liveness state (`state::is_alive` per capsule) and are restarted by
// future supervisor work, not by walking a kernel-resident
// `CORE_SERVICES` list. Until that supervisor lands, the microkernel
// init thread idles cooperatively after proof_io has handed off.
#[cfg(not(feature = "nonos-legacy-tree"))]
pub(crate) fn init_loop() -> ! {
    loop {
        crate::sched::yield_now();
    }
}
