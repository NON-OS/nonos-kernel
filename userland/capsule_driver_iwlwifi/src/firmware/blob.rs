// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use super::family::Family;

pub struct FirmwareBlob {
    pub name: &'static str,
    pub bytes: &'static [u8],
}

const F7265: &[u8] =
    include_bytes!("../../../../nonos-bootloader/firmware/intel/iwlwifi-7265D-29.ucode");
const F8265: &[u8] =
    include_bytes!("../../../../nonos-bootloader/firmware/intel/iwlwifi-8265-36.ucode");
const F9260: &[u8] =
    include_bytes!("../../../../nonos-bootloader/firmware/intel/iwlwifi-9260-th-b0-jf-b0-46.ucode");
const AX200: &[u8] =
    include_bytes!("../../../../nonos-bootloader/firmware/intel/iwlwifi-cc-a0-77.ucode");
const AX210: &[u8] =
    include_bytes!("../../../../nonos-bootloader/firmware/intel/iwlwifi-so-a0-gf-a0-86.ucode");

pub fn blob_for_family(family: Family) -> FirmwareBlob {
    match family {
        Family::F7265 => FirmwareBlob { name: "iwlwifi-7265D-29.ucode", bytes: F7265 },
        Family::F8265 => FirmwareBlob { name: "iwlwifi-8265-36.ucode", bytes: F8265 },
        Family::F9260 => FirmwareBlob { name: "iwlwifi-9260-th-b0-jf-b0-46.ucode", bytes: F9260 },
        Family::Ax200 => FirmwareBlob { name: "iwlwifi-cc-a0-77.ucode", bytes: AX200 },
        Family::Ax210 => FirmwareBlob { name: "iwlwifi-so-a0-gf-a0-86.ucode", bytes: AX210 },
    }
}
