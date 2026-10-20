// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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


//! The byte layout of the handoff, pinned. The loader and the kernel each
//! define it by hand; these same numbers sit in both crates, so a field moved
//! or resized on one side fails that side's build instead of the boot.

use core::mem::{offset_of, size_of};

use super::*;
use crate::firmware::FirmwareHandoff;

const _: () = assert!(size_of::<BootHandoffV1>() == 2008);
const _: () = assert!(size_of::<FramebufferInfo>() == 40);
const _: () = assert!(size_of::<MemoryMap>() == 24);
const _: () = assert!(size_of::<AcpiInfo>() == 8);
const _: () = assert!(size_of::<SmbiosInfo>() == 8);
const _: () = assert!(size_of::<Modules>() == 16);
const _: () = assert!(size_of::<Timing>() == 16);
const _: () = assert!(size_of::<Measurements>() == 40);
const _: () = assert!(size_of::<RngSeed>() == 32);
const _: () = assert!(size_of::<ZkAttestation>() == 72);
const _: () = assert!(size_of::<FirmwareHandoff>() == 1544);
const _: () = assert!(size_of::<AttestPolicy>() == 176);

const _: () = assert!(offset_of!(BootHandoffV1, magic) == 0);
const _: () = assert!(offset_of!(BootHandoffV1, version) == 4);
const _: () = assert!(offset_of!(BootHandoffV1, size) == 6);
const _: () = assert!(offset_of!(BootHandoffV1, flags) == 8);
const _: () = assert!(offset_of!(BootHandoffV1, entry_point) == 16);
const _: () = assert!(offset_of!(BootHandoffV1, fb) == 24);
const _: () = assert!(offset_of!(BootHandoffV1, mmap) == 64);
const _: () = assert!(offset_of!(BootHandoffV1, acpi) == 88);
const _: () = assert!(offset_of!(BootHandoffV1, smbios) == 96);
const _: () = assert!(offset_of!(BootHandoffV1, modules) == 104);
const _: () = assert!(offset_of!(BootHandoffV1, timing) == 120);
const _: () = assert!(offset_of!(BootHandoffV1, meas) == 136);
const _: () = assert!(offset_of!(BootHandoffV1, rng) == 176);
const _: () = assert!(offset_of!(BootHandoffV1, zk) == 208);
const _: () = assert!(offset_of!(BootHandoffV1, firmware) == 280);
const _: () = assert!(offset_of!(BootHandoffV1, cmdline_ptr) == 1824);
const _: () = assert!(offset_of!(BootHandoffV1, policy) == 1832);
