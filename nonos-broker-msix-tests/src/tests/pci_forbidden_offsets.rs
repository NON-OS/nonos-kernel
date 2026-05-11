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

//! Sweep every config-space offset a capsule might try to mutate
//! and confirm the validator rejects each. The list mirrors the
//! capsule-facing surface the kernel must own outright: BARs,
//! expansion ROM, interrupt line/pin, capability pointer, the
//! identification + status group at 0x00–0x06, and the
//! cacheline/latency/header/BIST quartet at 0x0C–0x0F.

use crate::broker::pci::allowlist::validate;
use crate::broker::pci::types::PciWriteError;

use super::pci_setup::{msix_info, req};

const FORBIDDEN: &[u32] = &[
    0x00, 0x02, 0x06, // VendorID, DeviceID, Status
    0x08, // Revision + Class group
    0x0C, 0x0D, 0x0E, 0x0F, // CacheLine, Latency, Header, BIST
    0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, // BAR0..BAR5
    0x28, // CardBus CIS pointer
    0x2C, 0x2E, // Subsystem vendor / id
    0x30, // Expansion ROM base
    0x34, // Capability pointer
    0x3C, 0x3D, // Interrupt Line, Interrupt Pin
];

#[test]
fn every_forbidden_offset_rejects() {
    for &off in FORBIDDEN {
        let err = validate(&req(off, 0), Some(&msix_info()), 0).unwrap_err();
        assert_eq!(err, PciWriteError::OffsetNotAllowed, "offset 0x{:02X}", off);
    }
}
