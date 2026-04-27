// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

pub mod acpi_tests;
pub mod boot_tests;
pub mod cpu_tests;
pub mod gdt_tests;
pub mod idt_tests;
pub mod time_tests;
pub mod uefi_tests;
pub mod vga_tests;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("Arch");

    suite.add(TestCase::new(
        "get_cpu_id_returns_valid",
        cpu_tests::test_get_cpu_id_returns_valid,
        "arch/cpu",
    ));
    suite.add(TestCase::new(
        "get_cpu_id_consistent",
        cpu_tests::test_get_cpu_id_consistent,
        "arch/cpu",
    ));
    suite.add(TestCase::new(
        "cpu_id_is_zero_on_bsp",
        cpu_tests::test_cpu_id_is_zero_on_bsp,
        "arch/cpu",
    ));

    suite.add(TestCase::new("gdt_constants", gdt_tests::test_gdt_constants, "arch/gdt"));
    suite.add(TestCase::new("segment_selectors", gdt_tests::test_segment_selectors, "arch/gdt"));
    suite.add(TestCase::new(
        "user_selectors_have_ring3",
        gdt_tests::test_user_selectors_have_ring3,
        "arch/gdt",
    ));
    suite.add(TestCase::new(
        "kernel_selectors_have_ring0",
        gdt_tests::test_kernel_selectors_have_ring0,
        "arch/gdt",
    ));
    suite.add(TestCase::new("ist_indices", gdt_tests::test_ist_indices, "arch/gdt"));
    suite.add(TestCase::new("ist_indices_valid", gdt_tests::test_ist_indices_valid, "arch/gdt"));
    suite.add(TestCase::new("gdt_entry_null", gdt_tests::test_gdt_entry_null, "arch/gdt"));
    suite.add(TestCase::new(
        "gdt_entry_kernel_code",
        gdt_tests::test_gdt_entry_kernel_code,
        "arch/gdt",
    ));
    suite.add(TestCase::new(
        "gdt_entry_kernel_data",
        gdt_tests::test_gdt_entry_kernel_data,
        "arch/gdt",
    ));
    suite.add(TestCase::new(
        "gdt_entry_user_code",
        gdt_tests::test_gdt_entry_user_code,
        "arch/gdt",
    ));
    suite.add(TestCase::new(
        "gdt_entry_user_data",
        gdt_tests::test_gdt_entry_user_data,
        "arch/gdt",
    ));
    suite.add(TestCase::new("gdt_entry_new", gdt_tests::test_gdt_entry_new, "arch/gdt"));
    suite.add(TestCase::new("gdt_entry_clone", gdt_tests::test_gdt_entry_clone, "arch/gdt"));
    suite.add(TestCase::new("gdt_entry_copy", gdt_tests::test_gdt_entry_copy, "arch/gdt"));
    suite.add(TestCase::new("selector_alignment", gdt_tests::test_selector_alignment, "arch/gdt"));
    suite.add(TestCase::new("tss_size_valid", gdt_tests::test_tss_size_valid, "arch/gdt"));
    suite.add(TestCase::new(
        "default_stack_size_aligned",
        gdt_tests::test_default_stack_size_aligned,
        "arch/gdt",
    ));

    suite.add(TestCase::new("idt_entries_count", idt_tests::test_idt_entries_count, "arch/idt"));
    suite.add(TestCase::new("kernel_cs", idt_tests::test_kernel_cs, "arch/idt"));
    suite.add(TestCase::new("gate_types", idt_tests::test_gate_types, "arch/idt"));
    suite.add(TestCase::new("privilege_levels", idt_tests::test_privilege_levels, "arch/idt"));
    suite.add(TestCase::new("present_flag", idt_tests::test_present_flag, "arch/idt"));
    suite.add(TestCase::new(
        "exception_vectors_order",
        idt_tests::test_exception_vectors_order,
        "arch/idt",
    ));
    suite.add(TestCase::new(
        "exception_vectors_high",
        idt_tests::test_exception_vectors_high,
        "arch/idt",
    ));
    suite.add(TestCase::new("irq_base", idt_tests::test_irq_base, "arch/idt"));
    suite.add(TestCase::new(
        "irq_base_after_exceptions",
        idt_tests::test_irq_base_after_exceptions,
        "arch/idt",
    ));
    suite.add(TestCase::new("ist_indices", idt_tests::test_ist_indices, "arch/idt"));
    suite.add(TestCase::new(
        "ist_indices_valid_range",
        idt_tests::test_ist_indices_valid_range,
        "arch/idt",
    ));
    suite.add(TestCase::new(
        "ist_indices_nonzero",
        idt_tests::test_ist_indices_nonzero,
        "arch/idt",
    ));
    suite.add(TestCase::new(
        "exceptions_below_irq_base",
        idt_tests::test_exceptions_below_irq_base,
        "arch/idt",
    ));
    suite.add(TestCase::new(
        "all_exceptions_unique",
        idt_tests::test_all_exceptions_unique,
        "arch/idt",
    ));
    suite.add(TestCase::new(
        "idt_size_fits_256_entries",
        idt_tests::test_idt_size_fits_256_entries,
        "arch/idt",
    ));

    suite.add(TestCase::new("table_signatures", acpi_tests::test_table_signatures, "arch/acpi"));
    suite.add(TestCase::new("rsdp_signature", acpi_tests::test_rsdp_signature, "arch/acpi"));
    suite.add(TestCase::new("rsdp_alignment", acpi_tests::test_rsdp_alignment, "arch/acpi"));
    suite.add(TestCase::new(
        "pm_profile_variants",
        acpi_tests::test_pm_profile_variants,
        "arch/acpi",
    ));
    suite.add(TestCase::new("madt_entry_types", acpi_tests::test_madt_entry_types, "arch/acpi"));
    suite.add(TestCase::new("srat_entry_types", acpi_tests::test_srat_entry_types, "arch/acpi"));
    suite.add(TestCase::new(
        "address_space_variants",
        acpi_tests::test_address_space_variants,
        "arch/acpi",
    ));
    suite.add(TestCase::new(
        "signatures_are_4_bytes",
        acpi_tests::test_signatures_are_4_bytes,
        "arch/acpi",
    ));
    suite.add(TestCase::new(
        "rsdp_signature_is_8_bytes",
        acpi_tests::test_rsdp_signature_is_8_bytes,
        "arch/acpi",
    ));
    suite.add(TestCase::new(
        "rsdp_alignment_power_of_two",
        acpi_tests::test_rsdp_alignment_power_of_two,
        "arch/acpi",
    ));

    suite.add(TestCase::new("boot_stack_base", boot_tests::test_boot_stack_base, "arch/boot"));
    suite.add(TestCase::new("boot_stack_size", boot_tests::test_boot_stack_size, "arch/boot"));
    suite.add(TestCase::new("boot_stack_top", boot_tests::test_boot_stack_top, "arch/boot"));
    suite.add(TestCase::new(
        "boot_stack_alignment",
        boot_tests::test_boot_stack_alignment,
        "arch/boot",
    ));
    suite.add(TestCase::new("msr_efer", boot_tests::test_msr_efer, "arch/boot"));
    suite.add(TestCase::new("msr_star", boot_tests::test_msr_star, "arch/boot"));
    suite.add(TestCase::new("msr_lstar", boot_tests::test_msr_lstar, "arch/boot"));
    suite.add(TestCase::new("msr_sfmask", boot_tests::test_msr_sfmask, "arch/boot"));
    suite.add(TestCase::new("msr_fs_base", boot_tests::test_msr_fs_base, "arch/boot"));
    suite.add(TestCase::new("msr_gs_base", boot_tests::test_msr_gs_base, "arch/boot"));
    suite.add(TestCase::new(
        "msr_kernel_gs_base",
        boot_tests::test_msr_kernel_gs_base,
        "arch/boot",
    ));
    suite.add(TestCase::new("efer_sce", boot_tests::test_efer_sce, "arch/boot"));
    suite.add(TestCase::new("efer_lme", boot_tests::test_efer_lme, "arch/boot"));
    suite.add(TestCase::new("efer_lma", boot_tests::test_efer_lma, "arch/boot"));
    suite.add(TestCase::new("efer_nxe", boot_tests::test_efer_nxe, "arch/boot"));
    suite.add(TestCase::new("cr0_pe", boot_tests::test_cr0_pe, "arch/boot"));
    suite.add(TestCase::new("cr0_mp", boot_tests::test_cr0_mp, "arch/boot"));
    suite.add(TestCase::new("cr0_em", boot_tests::test_cr0_em, "arch/boot"));
    suite.add(TestCase::new("cr0_ts", boot_tests::test_cr0_ts, "arch/boot"));
    suite.add(TestCase::new("cr0_et", boot_tests::test_cr0_et, "arch/boot"));
    suite.add(TestCase::new("cr0_ne", boot_tests::test_cr0_ne, "arch/boot"));
    suite.add(TestCase::new("cr0_wp", boot_tests::test_cr0_wp, "arch/boot"));
    suite.add(TestCase::new("cr0_am", boot_tests::test_cr0_am, "arch/boot"));
    suite.add(TestCase::new("cr0_nw", boot_tests::test_cr0_nw, "arch/boot"));
    suite.add(TestCase::new("cr0_cd", boot_tests::test_cr0_cd, "arch/boot"));
    suite.add(TestCase::new("cr0_pg", boot_tests::test_cr0_pg, "arch/boot"));
    suite.add(TestCase::new("cr4_vme", boot_tests::test_cr4_vme, "arch/boot"));
    suite.add(TestCase::new("cr4_pvi", boot_tests::test_cr4_pvi, "arch/boot"));
    suite.add(TestCase::new("cr4_tsd", boot_tests::test_cr4_tsd, "arch/boot"));
    suite.add(TestCase::new("cr4_de", boot_tests::test_cr4_de, "arch/boot"));
    suite.add(TestCase::new("cr4_pse", boot_tests::test_cr4_pse, "arch/boot"));
    suite.add(TestCase::new("cr4_pae", boot_tests::test_cr4_pae, "arch/boot"));
    suite.add(TestCase::new("cr4_mce", boot_tests::test_cr4_mce, "arch/boot"));
    suite.add(TestCase::new("cr4_pge", boot_tests::test_cr4_pge, "arch/boot"));
    suite.add(TestCase::new("cr4_pce", boot_tests::test_cr4_pce, "arch/boot"));
    suite.add(TestCase::new("cr4_osfxsr", boot_tests::test_cr4_osfxsr, "arch/boot"));
    suite.add(TestCase::new("cr4_osxmmexcpt", boot_tests::test_cr4_osxmmexcpt, "arch/boot"));
    suite.add(TestCase::new("cr4_umip", boot_tests::test_cr4_umip, "arch/boot"));
    suite.add(TestCase::new("cr4_fsgsbase", boot_tests::test_cr4_fsgsbase, "arch/boot"));
    suite.add(TestCase::new("cr4_pcide", boot_tests::test_cr4_pcide, "arch/boot"));
    suite.add(TestCase::new("cr4_osxsave", boot_tests::test_cr4_osxsave, "arch/boot"));
    suite.add(TestCase::new("cr4_smep", boot_tests::test_cr4_smep, "arch/boot"));
    suite.add(TestCase::new("cr4_smap", boot_tests::test_cr4_smap, "arch/boot"));
    suite.add(TestCase::new("xcr0_x87", boot_tests::test_xcr0_x87, "arch/boot"));
    suite.add(TestCase::new("xcr0_sse", boot_tests::test_xcr0_sse, "arch/boot"));
    suite.add(TestCase::new("xcr0_avx", boot_tests::test_xcr0_avx, "arch/boot"));
    suite.add(TestCase::new("xcr0_bndreg", boot_tests::test_xcr0_bndreg, "arch/boot"));
    suite.add(TestCase::new("xcr0_bndcsr", boot_tests::test_xcr0_bndcsr, "arch/boot"));
    suite.add(TestCase::new("xcr0_opmask", boot_tests::test_xcr0_opmask, "arch/boot"));
    suite.add(TestCase::new("xcr0_zmm_hi256", boot_tests::test_xcr0_zmm_hi256, "arch/boot"));
    suite.add(TestCase::new("xcr0_hi16_zmm", boot_tests::test_xcr0_hi16_zmm, "arch/boot"));
    suite.add(TestCase::new("xcr0_combined", boot_tests::test_xcr0_combined, "arch/boot"));
    suite.add(TestCase::new("boot_stage_count", boot_tests::test_boot_stage_count, "arch/boot"));
    suite.add(TestCase::new("boot_stage_entry", boot_tests::test_boot_stage_entry, "arch/boot"));
    suite.add(TestCase::new(
        "boot_stage_serial_init",
        boot_tests::test_boot_stage_serial_init,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stage_vga_init",
        boot_tests::test_boot_stage_vga_init,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stage_cpu_detect",
        boot_tests::test_boot_stage_cpu_detect,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stage_gdt_setup",
        boot_tests::test_boot_stage_gdt_setup,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stage_segment_reload",
        boot_tests::test_boot_stage_segment_reload,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stage_sse_enable",
        boot_tests::test_boot_stage_sse_enable,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stage_idt_setup",
        boot_tests::test_boot_stage_idt_setup,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stage_memory_validation",
        boot_tests::test_boot_stage_memory_validation,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stage_kernel_transfer",
        boot_tests::test_boot_stage_kernel_transfer,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stage_complete",
        boot_tests::test_boot_stage_complete,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stage_from_u8",
        boot_tests::test_boot_stage_from_u8,
        "arch/boot",
    ));
    suite.add(TestCase::new("boot_stage_as_u8", boot_tests::test_boot_stage_as_u8, "arch/boot"));
    suite.add(TestCase::new("boot_stage_next", boot_tests::test_boot_stage_next, "arch/boot"));
    suite.add(TestCase::new("boot_stage_prev", boot_tests::test_boot_stage_prev, "arch/boot"));
    suite.add(TestCase::new(
        "boot_stage_is_complete",
        boot_tests::test_boot_stage_is_complete,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stage_is_early",
        boot_tests::test_boot_stage_is_early,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stage_has_interrupts",
        boot_tests::test_boot_stage_has_interrupts,
        "arch/boot",
    ));
    suite.add(TestCase::new("boot_stage_all", boot_tests::test_boot_stage_all, "arch/boot"));
    suite.add(TestCase::new(
        "boot_stage_ordering",
        boot_tests::test_boot_stage_ordering,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stage_default",
        boot_tests::test_boot_stage_default,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "exception_context_default",
        boot_tests::test_exception_context_default,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "exception_context_instruction_pointer",
        boot_tests::test_exception_context_instruction_pointer,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "exception_context_stack_pointer",
        boot_tests::test_exception_context_stack_pointer,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "exception_context_code_segment",
        boot_tests::test_exception_context_code_segment,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "exception_context_is_user_mode",
        boot_tests::test_exception_context_is_user_mode,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "exception_context_is_kernel_mode",
        boot_tests::test_exception_context_is_kernel_mode,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "exception_context_has_error_code",
        boot_tests::test_exception_context_has_error_code,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stats_default",
        boot_tests::test_boot_stats_default,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stats_duration_tsc",
        boot_tests::test_boot_stats_duration_tsc,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stats_duration_tsc_zero",
        boot_tests::test_boot_stats_duration_tsc_zero,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stats_current_stage",
        boot_tests::test_boot_stats_current_stage,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stats_is_complete",
        boot_tests::test_boot_stats_is_complete,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "boot_stats_has_error",
        boot_tests::test_boot_stats_has_error,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "exception_context_copy",
        boot_tests::test_exception_context_copy,
        "arch/boot",
    ));
    suite.add(TestCase::new(
        "exception_context_clone",
        boot_tests::test_exception_context_clone,
        "arch/boot",
    ));
    suite.add(TestCase::new("boot_stats_copy", boot_tests::test_boot_stats_copy, "arch/boot"));

    suite.add(TestCase::new(
        "reset_type_variants",
        uefi_tests::test_reset_type_variants,
        "arch/uefi",
    ));
    suite.add(TestCase::new(
        "memory_type_conventional",
        uefi_tests::test_memory_type_conventional,
        "arch/uefi",
    ));
    suite.add(TestCase::new(
        "memory_type_loader_code",
        uefi_tests::test_memory_type_loader_code,
        "arch/uefi",
    ));
    suite.add(TestCase::new(
        "memory_type_loader_data",
        uefi_tests::test_memory_type_loader_data,
        "arch/uefi",
    ));
    suite.add(TestCase::new(
        "memory_type_boot_services_code",
        uefi_tests::test_memory_type_boot_services_code,
        "arch/uefi",
    ));
    suite.add(TestCase::new(
        "memory_type_boot_services_data",
        uefi_tests::test_memory_type_boot_services_data,
        "arch/uefi",
    ));
    suite.add(TestCase::new(
        "memory_type_runtime_services_code",
        uefi_tests::test_memory_type_runtime_services_code,
        "arch/uefi",
    ));
    suite.add(TestCase::new(
        "memory_type_runtime_services_data",
        uefi_tests::test_memory_type_runtime_services_data,
        "arch/uefi",
    ));
    suite.add(TestCase::new(
        "memory_type_acpi_reclaim",
        uefi_tests::test_memory_type_acpi_reclaim,
        "arch/uefi",
    ));
    suite.add(TestCase::new(
        "memory_type_acpi_nvs",
        uefi_tests::test_memory_type_acpi_nvs,
        "arch/uefi",
    ));
    suite.add(TestCase::new(
        "variable_attributes_nv",
        uefi_tests::test_variable_attributes_nv,
        "arch/uefi",
    ));
    suite.add(TestCase::new(
        "variable_attributes_bs",
        uefi_tests::test_variable_attributes_bs,
        "arch/uefi",
    ));
    suite.add(TestCase::new(
        "variable_attributes_rt",
        uefi_tests::test_variable_attributes_rt,
        "arch/uefi",
    ));
    suite.add(TestCase::new(
        "variable_attributes_combined",
        uefi_tests::test_variable_attributes_combined,
        "arch/uefi",
    ));
    suite.add(TestCase::new("crc32_new", uefi_tests::test_crc32_new, "arch/uefi"));
    suite.add(TestCase::new(
        "crc32_finalize_empty",
        uefi_tests::test_crc32_finalize_empty,
        "arch/uefi",
    ));
    suite.add(TestCase::new("crc32_update", uefi_tests::test_crc32_update, "arch/uefi"));

    suite.add(TestCase::new("vga_buffer_addr", vga_tests::test_vga_buffer_addr, "arch/vga"));
    suite.add(TestCase::new("screen_width", vga_tests::test_screen_width, "arch/vga"));
    suite.add(TestCase::new("screen_height", vga_tests::test_screen_height, "arch/vga"));
    suite.add(TestCase::new("screen_size", vga_tests::test_screen_size, "arch/vga"));
    suite.add(TestCase::new("bytes_per_char", vga_tests::test_bytes_per_char, "arch/vga"));
    suite.add(TestCase::new("vga_buffer_size", vga_tests::test_vga_buffer_size, "arch/vga"));
    suite.add(TestCase::new("max_consoles", vga_tests::test_max_consoles, "arch/vga"));
    suite.add(TestCase::new("scrollback_lines", vga_tests::test_scrollback_lines, "arch/vga"));
    suite.add(TestCase::new("color_values", vga_tests::test_color_values, "arch/vga"));
    suite.add(TestCase::new("color_name", vga_tests::test_color_name, "arch/vga"));
    suite.add(TestCase::new("color_code_new", vga_tests::test_color_code_new, "arch/vga"));
    suite.add(TestCase::new(
        "color_code_with_blink",
        vga_tests::test_color_code_with_blink,
        "arch/vga",
    ));
    suite.add(TestCase::new(
        "color_code_foreground",
        vga_tests::test_color_code_foreground,
        "arch/vga",
    ));
    suite.add(TestCase::new(
        "color_code_background",
        vga_tests::test_color_code_background,
        "arch/vga",
    ));
    suite.add(TestCase::new(
        "color_code_is_blinking",
        vga_tests::test_color_code_is_blinking,
        "arch/vga",
    ));
    suite.add(TestCase::new("color_code_value", vga_tests::test_color_code_value, "arch/vga"));
    suite.add(TestCase::new("color_code_default", vga_tests::test_color_code_default, "arch/vga"));
    suite.add(TestCase::new("color_code_copy", vga_tests::test_color_code_copy, "arch/vga"));
    suite.add(TestCase::new("color_code_eq", vga_tests::test_color_code_eq, "arch/vga"));
    suite.add(TestCase::new("screen_char_new", vga_tests::test_screen_char_new, "arch/vga"));
    suite.add(TestCase::new("screen_char_blank", vga_tests::test_screen_char_blank, "arch/vga"));
    suite.add(TestCase::new("screen_char_as_u16", vga_tests::test_screen_char_as_u16, "arch/vga"));
    suite.add(TestCase::new(
        "screen_char_default",
        vga_tests::test_screen_char_default,
        "arch/vga",
    ));
    suite.add(TestCase::new("screen_char_copy", vga_tests::test_screen_char_copy, "arch/vga"));
    suite.add(TestCase::new("screen_char_eq", vga_tests::test_screen_char_eq, "arch/vga"));
    suite.add(TestCase::new("console_new", vga_tests::test_console_new, "arch/vga"));
    suite.add(TestCase::new("console_clear", vga_tests::test_console_clear, "arch/vga"));
    suite.add(TestCase::new("console_write_byte", vga_tests::test_console_write_byte, "arch/vga"));
    suite.add(TestCase::new(
        "console_write_byte_newline",
        vga_tests::test_console_write_byte_newline,
        "arch/vga",
    ));
    suite.add(TestCase::new(
        "console_write_byte_carriage_return",
        vga_tests::test_console_write_byte_carriage_return,
        "arch/vga",
    ));
    suite.add(TestCase::new(
        "console_write_byte_tab",
        vga_tests::test_console_write_byte_tab,
        "arch/vga",
    ));
    suite.add(TestCase::new(
        "console_write_byte_backspace",
        vga_tests::test_console_write_byte_backspace,
        "arch/vga",
    ));
    suite.add(TestCase::new(
        "console_write_multiple_bytes",
        vga_tests::test_console_write_multiple_bytes,
        "arch/vga",
    ));
    suite.add(TestCase::new("console_set_color", vga_tests::test_console_set_color, "arch/vga"));
    suite.add(TestCase::new("console_wrap_line", vga_tests::test_console_wrap_line, "arch/vga"));
    suite.add(TestCase::new("console_scroll", vga_tests::test_console_scroll, "arch/vga"));
    suite.add(TestCase::new("color_clone", vga_tests::test_color_clone, "arch/vga"));
    suite.add(TestCase::new("screen_char_clone", vga_tests::test_screen_char_clone, "arch/vga"));
    suite.add(TestCase::new(
        "color_code_background_max",
        vga_tests::test_color_code_background_max,
        "arch/vga",
    ));
    suite.add(TestCase::new(
        "screen_position_calculation",
        vga_tests::test_screen_position_calculation,
        "arch/vga",
    ));
    suite.add(TestCase::new(
        "vga_address_calculation",
        vga_tests::test_vga_address_calculation,
        "arch/vga",
    ));

    suite.add(TestCase::new("pit_frequency", time_tests::test_pit_frequency, "arch/time"));
    suite.add(TestCase::new(
        "pit_frequency_approximately_1mhz",
        time_tests::test_pit_frequency_approximately_1mhz,
        "arch/time",
    ));
    suite.add(TestCase::new(
        "rtc_register_seconds",
        time_tests::test_rtc_register_seconds,
        "arch/time",
    ));
    suite.add(TestCase::new(
        "rtc_register_minutes",
        time_tests::test_rtc_register_minutes,
        "arch/time",
    ));
    suite.add(TestCase::new(
        "rtc_register_hours",
        time_tests::test_rtc_register_hours,
        "arch/time",
    ));
    suite.add(TestCase::new(
        "rtc_register_day_of_week",
        time_tests::test_rtc_register_day_of_week,
        "arch/time",
    ));
    suite.add(TestCase::new("rtc_register_day", time_tests::test_rtc_register_day, "arch/time"));
    suite.add(TestCase::new(
        "rtc_register_month",
        time_tests::test_rtc_register_month,
        "arch/time",
    ));
    suite.add(TestCase::new("rtc_register_year", time_tests::test_rtc_register_year, "arch/time"));
    suite.add(TestCase::new(
        "rtc_register_status_a",
        time_tests::test_rtc_register_status_a,
        "arch/time",
    ));
    suite.add(TestCase::new(
        "rtc_register_status_b",
        time_tests::test_rtc_register_status_b,
        "arch/time",
    ));
    suite.add(TestCase::new(
        "rtc_register_century",
        time_tests::test_rtc_register_century,
        "arch/time",
    ));

    let (_, failed, _) = suite.run_all();
    failed == 0
}
