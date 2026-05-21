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

pub(super) fn spawn() {
    spawn_rng();
    spawn_blk();
}

#[cfg(feature = "nonos-capsule-driver-virtio-rng")]
fn spawn_rng() {
    use crate::hardware::virtio_rng_capsule as c;
    super::boot::capsule(
        "DRIVER-VIRTIO-RNG",
        "driver_virtio_rng",
        c::spawn_driver_virtio_rng_capsule,
        c::shared_state,
    );
}
#[cfg(not(feature = "nonos-capsule-driver-virtio-rng"))]
fn spawn_rng() {}

#[cfg(feature = "nonos-capsule-driver-virtio-blk")]
fn spawn_blk() {
    use crate::hardware::virtio_blk_capsule as c;
    super::boot::capsule(
        "DRIVER-VIRTIO-BLK",
        "driver_virtio_blk",
        c::spawn_driver_virtio_blk_capsule,
        c::shared_state,
    );
}
#[cfg(not(feature = "nonos-capsule-driver-virtio-blk"))]
fn spawn_blk() {}
