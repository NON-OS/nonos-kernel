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

use super::constants::{cr4, intel_msr, smi_en, SMI_EN_OFFSET};
use super::error::SmmError;
use super::hw::{get_acpi_pm_base, read_cr4, read_msr, write_cr4, write_msr};
use super::manager::SMM_MANAGER;
use super::types::CpuVendor;

pub fn enable_smm_sandboxing() -> Result<(), SmmError> {
    let result = core::arch::x86_64::__cpuid(7);
    let smep_supported = (result.ebx & (1 << 7)) != 0;
    let smap_supported = (result.ebx & (1 << 20)) != 0;

    unsafe {
        let mut cr4_val = read_cr4();

        if smep_supported && (cr4_val & cr4::SMEP) == 0 {
            cr4_val |= cr4::SMEP;
            crate::log::info!("Enabling SMEP for SMM sandboxing");
        }

        if smap_supported && (cr4_val & cr4::SMAP) == 0 {
            cr4_val |= cr4::SMAP;
            crate::log::info!("Enabling SMAP for SMM sandboxing");
        }

        write_cr4(cr4_val);
    }

    crate::log::info!(
        "SMM sandboxing: SMEP={}, SMAP={}",
        smep_supported,
        smap_supported
    );
    Ok(())
}

pub fn enable_runtime_protection() -> Result<(), SmmError> {
    let vendor = SMM_MANAGER.cpu_vendor();

    if vendor != CpuVendor::Intel {
        return Ok(());
    }

    unsafe {
        let mut smm_feature = read_msr(intel_msr::SMM_FEATURE_CONTROL);

        if (smm_feature & intel_msr::SMM_CODE_CHK_EN) == 0 {
            smm_feature |= intel_msr::SMM_CODE_CHK_EN;
            write_msr(intel_msr::SMM_FEATURE_CONTROL, smm_feature);
            crate::log::info!("Enabled SMM_Code_Chk_En");
        }

        if (smm_feature & intel_msr::SMM_BWP) == 0 {
            smm_feature |= intel_msr::SMM_BWP;
            write_msr(intel_msr::SMM_FEATURE_CONTROL, smm_feature);
            crate::log::info!("Enabled SMM_BWP");
        }
    }

    crate::log::info!("SMM runtime protection enabled");
    Ok(())
}

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
        crate::log::info!(
            "Reduced SMI surface: 0x{:08x} -> 0x{:08x}",
            smi_en_val,
            new_smi_en
        );
    }

    crate::log::info!("SMI attack surface minimized");
    Ok(())
}
