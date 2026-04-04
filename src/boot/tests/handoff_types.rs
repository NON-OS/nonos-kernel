use crate::boot::handoff::types::*;
use core::mem::size_of;

#[test]
fn handoff_magic_value() {
    assert_eq!(HANDOFF_MAGIC, 0x4E_4F_4E_4F);
}

#[test]
fn handoff_version_value() {
    assert_eq!(HANDOFF_VERSION, 1);
}

#[test]
fn max_cmdline_value() {
    assert_eq!(MAX_CMDLINE, 4096);
}

#[test]
fn validate_cmdline_len_valid() {
    assert!(validate_cmdline_len(0));
    assert!(validate_cmdline_len(100));
    assert!(validate_cmdline_len(4096));
}

#[test]
fn validate_cmdline_len_invalid() {
    assert!(!validate_cmdline_len(4097));
    assert!(!validate_cmdline_len(10000));
}

#[test]
fn truncate_cmdline_short() {
    let short = "boot";
    assert_eq!(truncate_cmdline(short), "boot");
}

#[test]
fn truncate_cmdline_exact() {
    let exact: alloc::string::String = "a".repeat(4096);
    assert_eq!(truncate_cmdline(&exact).len(), 4096);
}

#[test]
fn truncate_cmdline_long() {
    let long: alloc::string::String = "b".repeat(5000);
    assert_eq!(truncate_cmdline(&long).len(), 4096);
}

#[test]
fn flags_wx() {
    assert_eq!(flags::WX, 1 << 0);
}

#[test]
fn flags_nxe() {
    assert_eq!(flags::NXE, 1 << 1);
}

#[test]
fn flags_smep() {
    assert_eq!(flags::SMEP, 1 << 2);
}

#[test]
fn flags_smap() {
    assert_eq!(flags::SMAP, 1 << 3);
}

#[test]
fn flags_umip() {
    assert_eq!(flags::UMIP, 1 << 4);
}

#[test]
fn flags_idmap_preserved() {
    assert_eq!(flags::IDMAP_PRESERVED, 1 << 5);
}

#[test]
fn flags_fb_available() {
    assert_eq!(flags::FB_AVAILABLE, 1 << 6);
}

#[test]
fn flags_acpi_available() {
    assert_eq!(flags::ACPI_AVAILABLE, 1 << 7);
}

#[test]
fn flags_tpm_measured() {
    assert_eq!(flags::TPM_MEASURED, 1 << 8);
}

#[test]
fn flags_secure_boot() {
    assert_eq!(flags::SECURE_BOOT, 1 << 9);
}

#[test]
fn flags_zk_attested() {
    assert_eq!(flags::ZK_ATTESTED, 1 << 10);
}

#[test]
fn flags_flag_names_empty() {
    let names = flags::flag_names(0);
    assert_eq!(names.len(), 0);
}

#[test]
fn flags_flag_names_single() {
    let names = flags::flag_names(flags::WX);
    assert!(names.len() >= 1);
}

#[test]
fn flags_flag_names_multiple() {
    let names = flags::flag_names(flags::WX | flags::NXE | flags::SMEP);
    assert!(names.len() >= 3);
}

#[test]
fn pixel_format_rgb() {
    assert_eq!(pixel_format::RGB, 0);
}

#[test]
fn pixel_format_bgr() {
    assert_eq!(pixel_format::BGR, 1);
}

#[test]
fn pixel_format_rgbx() {
    assert_eq!(pixel_format::RGBX, 2);
}

#[test]
fn pixel_format_bgrx() {
    assert_eq!(pixel_format::BGRX, 3);
}

#[test]
fn memory_type_reserved() {
    assert_eq!(memory_type::RESERVED, 0);
}

#[test]
fn memory_type_loader_code() {
    assert_eq!(memory_type::LOADER_CODE, 1);
}

#[test]
fn memory_type_loader_data() {
    assert_eq!(memory_type::LOADER_DATA, 2);
}

#[test]
fn memory_type_boot_services_code() {
    assert_eq!(memory_type::BOOT_SERVICES_CODE, 3);
}

#[test]
fn memory_type_boot_services_data() {
    assert_eq!(memory_type::BOOT_SERVICES_DATA, 4);
}

#[test]
fn memory_type_runtime_services_code() {
    assert_eq!(memory_type::RUNTIME_SERVICES_CODE, 5);
}

#[test]
fn memory_type_runtime_services_data() {
    assert_eq!(memory_type::RUNTIME_SERVICES_DATA, 6);
}

#[test]
fn memory_type_conventional() {
    assert_eq!(memory_type::CONVENTIONAL, 7);
}

#[test]
fn memory_type_unusable() {
    assert_eq!(memory_type::UNUSABLE, 8);
}

#[test]
fn memory_type_acpi_reclaim() {
    assert_eq!(memory_type::ACPI_RECLAIM, 9);
}

#[test]
fn memory_type_acpi_nvs() {
    assert_eq!(memory_type::ACPI_NVS, 10);
}

#[test]
fn memory_type_mmio() {
    assert_eq!(memory_type::MMIO, 11);
}

#[test]
fn memory_type_mmio_port_space() {
    assert_eq!(memory_type::MMIO_PORT_SPACE, 12);
}

#[test]
fn memory_type_pal_code() {
    assert_eq!(memory_type::PAL_CODE, 13);
}

#[test]
fn memory_type_persistent() {
    assert_eq!(memory_type::PERSISTENT, 14);
}

#[test]
fn memory_map_entry_size() {
    assert_eq!(size_of::<MemoryMapEntry>(), 40);
}

#[test]
fn memory_map_size() {
    assert_eq!(size_of::<MemoryMap>(), 24);
}

#[test]
fn memory_map_default() {
    let mmap = MemoryMap::default();
    assert_eq!(mmap.ptr, 0);
    assert_eq!(mmap.entry_size, 0);
    assert_eq!(mmap.entry_count, 0);
    assert_eq!(mmap.desc_version, 0);
}

#[test]
fn memory_map_entries_empty() {
    let mmap = MemoryMap::default();
    let entries = unsafe { mmap.entries() };
    assert!(entries.is_empty());
}

#[test]
fn framebuffer_info_size() {
    assert_eq!(size_of::<FramebufferInfo>(), 32);
}

#[test]
fn framebuffer_info_default() {
    let fb = FramebufferInfo::default();
    assert_eq!(fb.ptr, 0);
    assert_eq!(fb.size, 0);
    assert_eq!(fb.width, 0);
    assert_eq!(fb.height, 0);
    assert_eq!(fb.stride, 0);
    assert_eq!(fb.pixel_format, 0);
    assert_eq!(fb.cursor_y, 0);
}

#[test]
fn framebuffer_info_is_valid_default() {
    let fb = FramebufferInfo::default();
    assert!(!fb.is_valid());
}

#[test]
fn framebuffer_info_is_valid_valid() {
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
    assert!(fb.is_valid());
}

#[test]
fn framebuffer_info_is_valid_zero_ptr() {
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
    assert!(!fb.is_valid());
}

#[test]
fn framebuffer_info_is_valid_zero_width() {
    let fb = FramebufferInfo {
        ptr: 0xFD000000,
        size: 0x100000,
        width: 0,
        height: 600,
        stride: 3200,
        pixel_format: pixel_format::RGB,
        cursor_y: 0,
        reserved: 0,
    };
    assert!(!fb.is_valid());
}

#[test]
fn framebuffer_info_is_valid_zero_height() {
    let fb = FramebufferInfo {
        ptr: 0xFD000000,
        size: 0x100000,
        width: 800,
        height: 0,
        stride: 3200,
        pixel_format: pixel_format::RGB,
        cursor_y: 0,
        reserved: 0,
    };
    assert!(!fb.is_valid());
}

#[test]
fn framebuffer_info_is_valid_zero_stride() {
    let fb = FramebufferInfo {
        ptr: 0xFD000000,
        size: 0x100000,
        width: 800,
        height: 600,
        stride: 0,
        pixel_format: pixel_format::RGB,
        cursor_y: 0,
        reserved: 0,
    };
    assert!(!fb.is_valid());
}

#[test]
fn framebuffer_info_bytes_per_pixel_rgb() {
    let fb = FramebufferInfo {
        pixel_format: pixel_format::RGB,
        ..Default::default()
    };
    assert_eq!(fb.bytes_per_pixel(), 3);
}

#[test]
fn framebuffer_info_bytes_per_pixel_bgr() {
    let fb = FramebufferInfo {
        pixel_format: pixel_format::BGR,
        ..Default::default()
    };
    assert_eq!(fb.bytes_per_pixel(), 3);
}

#[test]
fn framebuffer_info_bytes_per_pixel_rgbx() {
    let fb = FramebufferInfo {
        pixel_format: pixel_format::RGBX,
        ..Default::default()
    };
    assert_eq!(fb.bytes_per_pixel(), 4);
}

#[test]
fn framebuffer_info_bytes_per_pixel_bgrx() {
    let fb = FramebufferInfo {
        pixel_format: pixel_format::BGRX,
        ..Default::default()
    };
    assert_eq!(fb.bytes_per_pixel(), 4);
}

#[test]
fn framebuffer_info_bytes_per_pixel_unknown() {
    let fb = FramebufferInfo {
        pixel_format: 99,
        ..Default::default()
    };
    assert_eq!(fb.bytes_per_pixel(), 4);
}

#[test]
fn acpi_info_size() {
    assert_eq!(size_of::<AcpiInfo>(), 8);
}

#[test]
fn acpi_info_default() {
    let acpi = AcpiInfo::default();
    assert_eq!(acpi.rsdp, 0);
}

#[test]
fn smbios_info_size() {
    assert_eq!(size_of::<SmbiosInfo>(), 8);
}

#[test]
fn smbios_info_default() {
    let smbios = SmbiosInfo::default();
    assert_eq!(smbios.entry, 0);
}

#[test]
fn module_struct_size() {
    assert_eq!(size_of::<Module>(), 24);
}

#[test]
fn module_default() {
    let module = Module::default();
    assert_eq!(module.base, 0);
    assert_eq!(module.size, 0);
    assert_eq!(module.kind, 0);
    assert_eq!(module.reserved, 0);
}

#[test]
fn modules_size() {
    assert_eq!(size_of::<Modules>(), 16);
}

#[test]
fn modules_default() {
    let modules = Modules::default();
    assert_eq!(modules.ptr, 0);
    assert_eq!(modules.count, 0);
}

#[test]
fn modules_modules_empty() {
    let modules = Modules::default();
    let mods = unsafe { modules.modules() };
    assert!(mods.is_empty());
}

#[test]
fn timing_size() {
    assert_eq!(size_of::<Timing>(), 16);
}

#[test]
fn timing_default() {
    let timing = Timing::default();
    assert_eq!(timing.tsc_hz, 0);
    assert_eq!(timing.unix_epoch_ms, 0);
}

#[test]
fn measurements_size() {
    assert_eq!(size_of::<Measurements>(), 40);
}

#[test]
fn measurements_default() {
    let meas = Measurements::default();
    assert_eq!(meas.kernel_blake3, [0; 32]);
    assert_eq!(meas.kernel_sig_ok, 0);
    assert_eq!(meas.secure_boot, 0);
    assert_eq!(meas.zk_attestation_ok, 0);
    assert_eq!(meas.reserved, [0; 5]);
}

#[test]
fn zk_attestation_size() {
    assert_eq!(size_of::<ZkAttestation>(), 72);
}

#[test]
fn zk_attestation_default() {
    let zk = ZkAttestation::default();
    assert_eq!(zk.verified, 0);
    assert_eq!(zk.flags, 0);
    assert_eq!(zk.reserved, [0; 6]);
    assert_eq!(zk.program_hash, [0; 32]);
    assert_eq!(zk.capsule_commitment, [0; 32]);
}

#[test]
fn rng_seed_size() {
    assert_eq!(size_of::<RngSeed>(), 32);
}

#[test]
fn rng_seed_default() {
    let rng = RngSeed::default();
    assert_eq!(rng.seed32, [0; 32]);
}

#[test]
fn boot_handoff_v1_default_is_valid() {
    let handoff = BootHandoffV1::default();
    assert!(handoff.is_valid());
}

#[test]
fn boot_handoff_v1_default_magic() {
    let handoff = BootHandoffV1::default();
    assert_eq!(handoff.magic, HANDOFF_MAGIC);
}

#[test]
fn boot_handoff_v1_default_version() {
    let handoff = BootHandoffV1::default();
    assert_eq!(handoff.version, HANDOFF_VERSION);
}

#[test]
fn boot_handoff_v1_default_size() {
    let handoff = BootHandoffV1::default();
    assert_eq!(handoff.size as usize, size_of::<BootHandoffV1>());
}

#[test]
fn boot_handoff_v1_invalid_magic() {
    let mut handoff = BootHandoffV1::default();
    handoff.magic = 0x12345678;
    assert!(!handoff.is_valid());
}

#[test]
fn boot_handoff_v1_invalid_version() {
    let mut handoff = BootHandoffV1::default();
    handoff.version = 99;
    assert!(!handoff.is_valid());
}

#[test]
fn boot_handoff_v1_invalid_size() {
    let mut handoff = BootHandoffV1::default();
    handoff.size = 64;
    assert!(!handoff.is_valid());
}

#[test]
fn boot_handoff_v1_has_flag_none() {
    let handoff = BootHandoffV1::default();
    assert!(!handoff.has_flag(flags::FB_AVAILABLE));
    assert!(!handoff.has_flag(flags::ACPI_AVAILABLE));
}

#[test]
fn boot_handoff_v1_has_flag_single() {
    let mut handoff = BootHandoffV1::default();
    handoff.flags = flags::FB_AVAILABLE;
    assert!(handoff.has_flag(flags::FB_AVAILABLE));
    assert!(!handoff.has_flag(flags::ACPI_AVAILABLE));
}

#[test]
fn boot_handoff_v1_has_flag_multiple() {
    let mut handoff = BootHandoffV1::default();
    handoff.flags = flags::FB_AVAILABLE | flags::ACPI_AVAILABLE | flags::NXE;
    assert!(handoff.has_flag(flags::FB_AVAILABLE));
    assert!(handoff.has_flag(flags::ACPI_AVAILABLE));
    assert!(handoff.has_flag(flags::NXE));
    assert!(!handoff.has_flag(flags::SMEP));
}

#[test]
fn boot_handoff_v1_framebuffer_none() {
    let handoff = BootHandoffV1::default();
    assert!(handoff.framebuffer().is_none());
}

#[test]
fn boot_handoff_v1_framebuffer_flag_but_null_ptr() {
    let mut handoff = BootHandoffV1::default();
    handoff.flags = flags::FB_AVAILABLE;
    assert!(handoff.framebuffer().is_none());
}

#[test]
fn boot_handoff_v1_framebuffer_valid() {
    let mut handoff = BootHandoffV1::default();
    handoff.flags = flags::FB_AVAILABLE;
    handoff.fb.ptr = 0xFD000000;
    assert!(handoff.framebuffer().is_some());
}

#[test]
fn boot_handoff_v1_acpi_rsdp_none() {
    let handoff = BootHandoffV1::default();
    assert!(handoff.acpi_rsdp().is_none());
}

#[test]
fn boot_handoff_v1_acpi_rsdp_flag_but_null() {
    let mut handoff = BootHandoffV1::default();
    handoff.flags = flags::ACPI_AVAILABLE;
    assert!(handoff.acpi_rsdp().is_none());
}

#[test]
fn boot_handoff_v1_acpi_rsdp_valid() {
    let mut handoff = BootHandoffV1::default();
    handoff.flags = flags::ACPI_AVAILABLE;
    handoff.acpi.rsdp = 0xFED00000;
    assert_eq!(handoff.acpi_rsdp(), Some(0xFED00000));
}

#[test]
fn boot_handoff_v1_secure_boot_disabled() {
    let handoff = BootHandoffV1::default();
    assert!(!handoff.secure_boot_enabled());
}

#[test]
fn boot_handoff_v1_secure_boot_via_flag() {
    let mut handoff = BootHandoffV1::default();
    handoff.flags = flags::SECURE_BOOT;
    assert!(handoff.secure_boot_enabled());
}

#[test]
fn boot_handoff_v1_secure_boot_via_meas() {
    let mut handoff = BootHandoffV1::default();
    handoff.meas.secure_boot = 1;
    assert!(handoff.secure_boot_enabled());
}

#[test]
fn boot_handoff_v1_kernel_verified_false() {
    let handoff = BootHandoffV1::default();
    assert!(!handoff.kernel_verified());
}

#[test]
fn boot_handoff_v1_kernel_verified_true() {
    let mut handoff = BootHandoffV1::default();
    handoff.meas.kernel_sig_ok = 1;
    assert!(handoff.kernel_verified());
}

#[test]
fn boot_handoff_v1_clone() {
    let handoff = BootHandoffV1::default();
    let cloned = handoff.clone();
    assert_eq!(handoff.magic, cloned.magic);
    assert_eq!(handoff.version, cloned.version);
    assert_eq!(handoff.size, cloned.size);
}

#[test]
fn boot_handoff_v1_copy() {
    let handoff = BootHandoffV1::default();
    let copied = handoff;
    assert_eq!(handoff.magic, copied.magic);
}

#[test]
fn boot_handoff_v1_debug() {
    let handoff = BootHandoffV1::default();
    let debug = alloc::format!("{:?}", handoff);
    assert!(debug.contains("BootHandoffV1"));
}
