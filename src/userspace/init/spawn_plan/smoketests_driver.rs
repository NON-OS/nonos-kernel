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
    virtio_rng();
    virtio_blk();
    virtio_net();
    ps2_input();
    xhci();
}

#[cfg(feature = "nonos-driver-virtio-rng-smoketest")]
fn virtio_rng() {
    super::super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_DRIVER,
        crate::hardware::virtio_rng_capsule::smoketest::run,
    );
}
#[cfg(not(feature = "nonos-driver-virtio-rng-smoketest"))]
fn virtio_rng() {}

#[cfg(feature = "nonos-driver-virtio-blk-smoketest")]
fn virtio_blk() {
    super::super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_DRIVER,
        crate::hardware::virtio_blk_capsule::smoketest::run,
    );
}
#[cfg(not(feature = "nonos-driver-virtio-blk-smoketest"))]
fn virtio_blk() {}

#[cfg(feature = "nonos-driver-virtio-net-smoketest")]
fn virtio_net() {
    super::super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_DRIVER,
        crate::hardware::virtio_net_capsule::smoketest::run,
    );
}
#[cfg(not(feature = "nonos-driver-virtio-net-smoketest"))]
fn virtio_net() {}

#[cfg(feature = "nonos-driver-ps2-input-smoketest")]
fn ps2_input() {
    super::super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_DRIVER,
        crate::hardware::ps2_kbd_capsule::smoketest::run,
    );
}
#[cfg(not(feature = "nonos-driver-ps2-input-smoketest"))]
fn ps2_input() {}

#[cfg(feature = "nonos-driver-xhci-smoketest")]
fn xhci() {
    super::super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_DRIVER,
        crate::hardware::xhci_capsule::smoketest::run,
    );
}
#[cfg(not(feature = "nonos-driver-xhci-smoketest"))]
fn xhci() {}
