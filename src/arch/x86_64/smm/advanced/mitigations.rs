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

use crate::arch::x86_64::smm::constants::{intel_msr, smi_en, SMI_EN_OFFSET};
use crate::arch::x86_64::smm::error::SmmError;
use crate::arch::x86_64::smm::hw::{get_acpi_pm_base, read_msr, write_msr};

pub fn apply_mitigations() -> Result<(), SmmError> {
    unsafe {
        let feature_control = read_msr(intel_msr::IA32_FEATURE_CONTROL);
        if (feature_control & 0x1) == 0 {
            write_msr(intel_msr::IA32_FEATURE_CONTROL, feature_control | 0x1);
            crate::log::info!("Locked IA32_FEATURE_CONTROL");
        }
    }

    if let Some(pm_base) = get_acpi_pm_base() {
        let smi_en_val = unsafe {
            x86_64::instructions::port::Port::<u32>::new(pm_base + SMI_EN_OFFSET).read()
        };
        if (smi_en_val & smi_en::LEGACY_USB_EN) != 0 {
            unsafe {
                x86_64::instructions::port::Port::<u32>::new(pm_base + SMI_EN_OFFSET)
                    .write(smi_en_val & !smi_en::LEGACY_USB_EN);
            }
            crate::log::info!("Disabled legacy USB SMI");
        }
    }

    crate::log::info!("SMM vulnerability mitigations applied");
    Ok(())
}

pub fn minimize_smi_surface() -> Result<(), SmmError> {
    let pm_base = get_acpi_pm_base().ok_or(SmmError::AcpiPmBaseNotFound)?;
    let smi_en_val = unsafe {
        x86_64::instructions::port::Port::<u32>::new(pm_base + SMI_EN_OFFSET).read()
    };

    let essential = smi_en::GBL_SMI_EN | smi_en::APMC_EN;
    let new_smi_en = smi_en_val & essential;

    if new_smi_en != smi_en_val {
        unsafe {
            x86_64::instructions::port::Port::<u32>::new(pm_base + SMI_EN_OFFSET).write(new_smi_en);
        }
        crate::log::info!("Reduced SMI surface: 0x{:08x} -> 0x{:08x}", smi_en_val, new_smi_en);
    }

    crate::log::info!("SMI attack surface minimized");
    Ok(())
}
