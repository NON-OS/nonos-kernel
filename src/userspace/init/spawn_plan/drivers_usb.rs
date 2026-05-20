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
    spawn_xhci();
    spawn_usb_hid();
    spawn_usb_msc();
}

#[cfg(feature = "nonos-capsule-driver-xhci")]
fn spawn_xhci() {
    use crate::hardware::xhci_capsule as c;
    super::boot::capsule(
        "DRIVER-XHCI",
        "driver_xhci",
        c::spawn_driver_xhci_capsule,
        c::shared_state,
    );
}

#[cfg(not(feature = "nonos-capsule-driver-xhci"))]
fn spawn_xhci() {}

#[cfg(feature = "nonos-capsule-driver-usb-hid")]
fn spawn_usb_hid() {
    use crate::userspace::capsule_driver_usb_hid as c;
    super::boot::capsule(
        "DRIVER-USB-HID",
        "driver_usb_hid",
        c::spawn_driver_usb_hid_capsule,
        c::shared_state,
    );
}

#[cfg(not(feature = "nonos-capsule-driver-usb-hid"))]
fn spawn_usb_hid() {}

#[cfg(feature = "nonos-capsule-driver-usb-msc")]
fn spawn_usb_msc() {
    use crate::userspace::capsule_driver_usb_msc as c;
    super::boot::capsule(
        "DRIVER-USB-MSC",
        "driver_usb_msc",
        c::spawn_driver_usb_msc_capsule,
        c::shared_state,
    );
}

#[cfg(not(feature = "nonos-capsule-driver-usb-msc"))]
fn spawn_usb_msc() {}
