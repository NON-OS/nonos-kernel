// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::boot::handoff::types::*;
use crate::test::framework::TestResult;
use core::mem::size_of;

pub(crate) fn test_handoff_magic_value() -> TestResult {
    if HANDOFF_MAGIC != 0x4E_4F_4E_4F {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_handoff_version_value() -> TestResult {
    if HANDOFF_VERSION != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_cmdline_value() -> TestResult {
    if MAX_CMDLINE != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_cmdline_len_valid() -> TestResult {
    if !validate_cmdline_len(0) {
        return TestResult::Fail;
    }
    if !validate_cmdline_len(100) {
        return TestResult::Fail;
    }
    if !validate_cmdline_len(4096) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_cmdline_len_invalid() -> TestResult {
    if validate_cmdline_len(4097) {
        return TestResult::Fail;
    }
    if validate_cmdline_len(10000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_truncate_cmdline_short() -> TestResult {
    if truncate_cmdline("boot") != "boot" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_wx() -> TestResult {
    if flags::WX != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_nxe() -> TestResult {
    if flags::NXE != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_smep() -> TestResult {
    if flags::SMEP != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_smap() -> TestResult {
    if flags::SMAP != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_umip() -> TestResult {
    if flags::UMIP != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_idmap_preserved() -> TestResult {
    if flags::IDMAP_PRESERVED != 1 << 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_fb_available() -> TestResult {
    if flags::FB_AVAILABLE != 1 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_acpi_available() -> TestResult {
    if flags::ACPI_AVAILABLE != 1 << 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_tpm_measured() -> TestResult {
    if flags::TPM_MEASURED != 1 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_secure_boot() -> TestResult {
    if flags::SECURE_BOOT != 1 << 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_zk_attested() -> TestResult {
    if flags::ZK_ATTESTED != 1 << 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_flag_names_empty() -> TestResult {
    let names = flags::flag_names(0);
    if names.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_flag_names_single() -> TestResult {
    let names = flags::flag_names(flags::WX);
    if names.len() < 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_flag_names_multiple() -> TestResult {
    let names = flags::flag_names(flags::WX | flags::NXE | flags::SMEP);
    if names.len() < 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_rgb() -> TestResult {
    if pixel_format::RGB != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_bgr() -> TestResult {
    if pixel_format::BGR != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_rgbx() -> TestResult {
    if pixel_format::RGBX != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_bgrx() -> TestResult {
    if pixel_format::BGRX != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_reserved() -> TestResult {
    if memory_type::RESERVED != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_loader_code() -> TestResult {
    if memory_type::LOADER_CODE != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_loader_data() -> TestResult {
    if memory_type::LOADER_DATA != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_boot_services_code() -> TestResult {
    if memory_type::BOOT_SERVICES_CODE != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_boot_services_data() -> TestResult {
    if memory_type::BOOT_SERVICES_DATA != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_runtime_services_code() -> TestResult {
    if memory_type::RUNTIME_SERVICES_CODE != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_runtime_services_data() -> TestResult {
    if memory_type::RUNTIME_SERVICES_DATA != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_conventional() -> TestResult {
    if memory_type::CONVENTIONAL != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_unusable() -> TestResult {
    if memory_type::UNUSABLE != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_acpi_reclaim() -> TestResult {
    if memory_type::ACPI_RECLAIM != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_acpi_nvs() -> TestResult {
    if memory_type::ACPI_NVS != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_mmio() -> TestResult {
    if memory_type::MMIO != 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_mmio_port_space() -> TestResult {
    if memory_type::MMIO_PORT_SPACE != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_pal_code() -> TestResult {
    if memory_type::PAL_CODE != 13 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_persistent() -> TestResult {
    if memory_type::PERSISTENT != 14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_map_entry_size() -> TestResult {
    if size_of::<MemoryMapEntry>() != 40 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_map_size() -> TestResult {
    if size_of::<MemoryMap>() != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_map_default() -> TestResult {
    let mmap = MemoryMap::default();
    if mmap.ptr != 0 {
        return TestResult::Fail;
    }
    if mmap.entry_size != 0 {
        return TestResult::Fail;
    }
    if mmap.entry_count != 0 {
        return TestResult::Fail;
    }
    if mmap.desc_version != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_struct_size() -> TestResult {
    if size_of::<FramebufferInfo>() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_default() -> TestResult {
    let fb = FramebufferInfo::default();
    if fb.ptr != 0 {
        return TestResult::Fail;
    }
    if fb.size != 0 {
        return TestResult::Fail;
    }
    if fb.width != 0 {
        return TestResult::Fail;
    }
    if fb.height != 0 {
        return TestResult::Fail;
    }
    if fb.stride != 0 {
        return TestResult::Fail;
    }
    if fb.pixel_format != 0 {
        return TestResult::Fail;
    }
    if fb.cursor_y != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_is_valid_default() -> TestResult {
    let fb = FramebufferInfo::default();
    if fb.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_is_valid_valid() -> TestResult {
    let fb = FramebufferInfo {
        ptr: 0xFD000000,
        size: 0x100000,
        width: 800,
        height: 600,
        stride: 3200,
        pixel_format: pixel_format::RGB,
        cursor_y: 0,
        reserved: 0,
    };
    if !fb.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_is_valid_zero_ptr() -> TestResult {
    let fb = FramebufferInfo {
        ptr: 0,
        size: 0x100000,
        width: 800,
        height: 600,
        stride: 3200,
        pixel_format: pixel_format::RGB,
        cursor_y: 0,
        reserved: 0,
    };
    if fb.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_bytes_per_pixel_rgb() -> TestResult {
    let fb = FramebufferInfo { pixel_format: pixel_format::RGB, ..Default::default() };
    if fb.bytes_per_pixel() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_bytes_per_pixel_bgr() -> TestResult {
    let fb = FramebufferInfo { pixel_format: pixel_format::BGR, ..Default::default() };
    if fb.bytes_per_pixel() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_bytes_per_pixel_rgbx() -> TestResult {
    let fb = FramebufferInfo { pixel_format: pixel_format::RGBX, ..Default::default() };
    if fb.bytes_per_pixel() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_bytes_per_pixel_bgrx() -> TestResult {
    let fb = FramebufferInfo { pixel_format: pixel_format::BGRX, ..Default::default() };
    if fb.bytes_per_pixel() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_acpi_info_size() -> TestResult {
    if size_of::<AcpiInfo>() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_acpi_info_default() -> TestResult {
    let acpi = AcpiInfo::default();
    if acpi.rsdp != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_smbios_info_size() -> TestResult {
    if size_of::<SmbiosInfo>() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_smbios_info_default() -> TestResult {
    let smbios = SmbiosInfo::default();
    if smbios.entry != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_module_struct_size() -> TestResult {
    if size_of::<Module>() != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_module_default() -> TestResult {
    let module = Module::default();
    if module.base != 0 {
        return TestResult::Fail;
    }
    if module.size != 0 {
        return TestResult::Fail;
    }
    if module.kind != 0 {
        return TestResult::Fail;
    }
    if module.reserved != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_modules_size() -> TestResult {
    if size_of::<Modules>() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_modules_default() -> TestResult {
    let modules = Modules::default();
    if modules.ptr != 0 {
        return TestResult::Fail;
    }
    if modules.count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_timing_size() -> TestResult {
    if size_of::<Timing>() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_timing_default() -> TestResult {
    let timing = Timing::default();
    if timing.tsc_hz != 0 {
        return TestResult::Fail;
    }
    if timing.unix_epoch_ms != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_measurements_size() -> TestResult {
    if size_of::<Measurements>() != 40 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_measurements_default() -> TestResult {
    let meas = Measurements::default();
    if meas.kernel_blake3 != [0; 32] {
        return TestResult::Fail;
    }
    if meas.kernel_sig_ok != 0 {
        return TestResult::Fail;
    }
    if meas.secure_boot != 0 {
        return TestResult::Fail;
    }
    if meas.zk_attestation_ok != 0 {
        return TestResult::Fail;
    }
    if meas.reserved != [0; 5] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zk_attestation_size() -> TestResult {
    if size_of::<ZkAttestation>() != 72 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zk_attestation_default() -> TestResult {
    let zk = ZkAttestation::default();
    if zk.verified != 0 {
        return TestResult::Fail;
    }
    if zk.flags != 0 {
        return TestResult::Fail;
    }
    if zk.reserved != [0; 6] {
        return TestResult::Fail;
    }
    if zk.program_hash != [0; 32] {
        return TestResult::Fail;
    }
    if zk.capsule_commitment != [0; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rng_seed_size() -> TestResult {
    if size_of::<RngSeed>() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rng_seed_default() -> TestResult {
    let rng = RngSeed::default();
    if rng.seed32 != [0; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_default_is_valid() -> TestResult {
    let handoff = BootHandoffV1::default();
    if !handoff.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_default_magic() -> TestResult {
    let handoff = BootHandoffV1::default();
    if handoff.magic != HANDOFF_MAGIC {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_default_version() -> TestResult {
    let handoff = BootHandoffV1::default();
    if handoff.version != HANDOFF_VERSION {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_default_size() -> TestResult {
    let handoff = BootHandoffV1::default();
    if handoff.size as usize != size_of::<BootHandoffV1>() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_invalid_magic() -> TestResult {
    let mut handoff = BootHandoffV1::default();
    handoff.magic = 0x12345678;
    if handoff.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_invalid_version() -> TestResult {
    let mut handoff = BootHandoffV1::default();
    handoff.version = 99;
    if handoff.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_invalid_size() -> TestResult {
    let mut handoff = BootHandoffV1::default();
    handoff.size = 64;
    if handoff.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_has_flag_none() -> TestResult {
    let handoff = BootHandoffV1::default();
    if handoff.has_flag(flags::FB_AVAILABLE) {
        return TestResult::Fail;
    }
    if handoff.has_flag(flags::ACPI_AVAILABLE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_has_flag_single() -> TestResult {
    let mut handoff = BootHandoffV1::default();
    handoff.flags = flags::FB_AVAILABLE;
    if !handoff.has_flag(flags::FB_AVAILABLE) {
        return TestResult::Fail;
    }
    if handoff.has_flag(flags::ACPI_AVAILABLE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_has_flag_multiple() -> TestResult {
    let mut handoff = BootHandoffV1::default();
    handoff.flags = flags::FB_AVAILABLE | flags::ACPI_AVAILABLE | flags::NXE;
    if !handoff.has_flag(flags::FB_AVAILABLE) {
        return TestResult::Fail;
    }
    if !handoff.has_flag(flags::ACPI_AVAILABLE) {
        return TestResult::Fail;
    }
    if !handoff.has_flag(flags::NXE) {
        return TestResult::Fail;
    }
    if handoff.has_flag(flags::SMEP) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_framebuffer_none() -> TestResult {
    let handoff = BootHandoffV1::default();
    if handoff.framebuffer().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_framebuffer_flag_but_null_ptr() -> TestResult {
    let mut handoff = BootHandoffV1::default();
    handoff.flags = flags::FB_AVAILABLE;
    if handoff.framebuffer().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_framebuffer_valid() -> TestResult {
    let mut handoff = BootHandoffV1::default();
    handoff.flags = flags::FB_AVAILABLE;
    handoff.fb.ptr = 0xFD000000;
    if handoff.framebuffer().is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_acpi_rsdp_none() -> TestResult {
    let handoff = BootHandoffV1::default();
    if handoff.acpi_rsdp().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_acpi_rsdp_flag_but_null() -> TestResult {
    let mut handoff = BootHandoffV1::default();
    handoff.flags = flags::ACPI_AVAILABLE;
    if handoff.acpi_rsdp().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_acpi_rsdp_valid() -> TestResult {
    let mut handoff = BootHandoffV1::default();
    handoff.flags = flags::ACPI_AVAILABLE;
    handoff.acpi.rsdp = 0xFED00000;
    if handoff.acpi_rsdp() != Some(0xFED00000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_secure_boot_disabled() -> TestResult {
    let handoff = BootHandoffV1::default();
    if handoff.secure_boot_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_secure_boot_via_flag() -> TestResult {
    let mut handoff = BootHandoffV1::default();
    handoff.flags = flags::SECURE_BOOT;
    if !handoff.secure_boot_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_secure_boot_via_meas() -> TestResult {
    let mut handoff = BootHandoffV1::default();
    handoff.meas.secure_boot = 1;
    if !handoff.secure_boot_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_kernel_verified_false() -> TestResult {
    let handoff = BootHandoffV1::default();
    if handoff.kernel_verified() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_kernel_verified_true() -> TestResult {
    let mut handoff = BootHandoffV1::default();
    handoff.meas.kernel_sig_ok = 1;
    if !handoff.kernel_verified() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_clone() -> TestResult {
    let handoff = BootHandoffV1::default();
    let cloned = handoff.clone();
    if handoff.magic != cloned.magic {
        return TestResult::Fail;
    }
    if handoff.version != cloned.version {
        return TestResult::Fail;
    }
    if handoff.size != cloned.size {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_handoff_v1_copy() -> TestResult {
    let handoff = BootHandoffV1::default();
    let copied = handoff;
    if handoff.magic != copied.magic {
        return TestResult::Fail;
    }
    TestResult::Pass
}
