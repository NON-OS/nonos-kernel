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

pub(super) fn run_all() {
    vfs();
    market();
}

#[cfg(feature = "nonos-vfs-smoketest")]
fn vfs() {
    super::super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_VFS,
        crate::fs::vfs_capsule::smoketest::run,
    );
}
#[cfg(not(feature = "nonos-vfs-smoketest"))]
fn vfs() {}

#[cfg(feature = "nonos-market-smoketest")]
fn market() {
    super::super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_APPS,
        crate::security::market_capsule::smoketest::run,
    );
}
#[cfg(not(feature = "nonos-market-smoketest"))]
fn market() {}
