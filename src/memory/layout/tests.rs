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

use super::*;
use super::constants::*;
use super::error::LayoutError;

// ============================================================================
// CONSTANTS TESTS
// ============================================================================

#[test]
fn test_page_size_constants() {
    assert_eq!(PAGE_SIZE, 4096);
    assert_eq!(PAGE_SIZE_U64, 4096);
    assert_eq!(PAGE_MASK, !0xFFF);
    assert_eq!(HUGE_PAGE_2M, 2 * 1024 * 1024);
    assert_eq!(HUGE_PAGE_1G, 1024 * 1024 * 1024);
}

#[test]
fn test_canonical_address_constants() {
    assert_eq!(CANONICAL_LOW_MAX, 0x0000_7FFF_FFFF_FFFF);
    assert_eq!(CANONICAL_HIGH_MIN, 0xFFFF_8000_0000_0000);
    assert!(CANONICAL_LOW_MAX < CANONICAL_HIGH_MIN);
}

#[test]
fn test_kernel_base_constant() {
    assert_eq!(KERNEL_BASE, 0xFFFF_FFFF_8000_0000);
    assert!(KERNEL_BASE >= CANONICAL_HIGH_MIN);
}

#[test]
fn test_user_space_constants() {
    assert_eq!(USER_BASE, 0);
    assert_eq!(USER_TOP, CANONICAL_LOW_MAX);
}

#[test]
fn test_heap_constants() {
    assert_eq!(KHEAP_BASE, 0xFFFF_FF00_0000_0000);
    assert_eq!(KHEAP_SIZE, 0x0000_0000_1000_0000); // 256 MiB
    assert!(KHEAP_BASE >= CANONICAL_HIGH_MIN);
}

#[test]
fn test_vm_constants() {
    assert_eq!(KVM_BASE, 0xFFFF_FF10_0000_0000);
    assert_eq!(KVM_SIZE, 0x0000_0000_2000_0000); // 512 MiB
    assert!(KVM_BASE > KHEAP_BASE);
}

#[test]
fn test_mmio_constants() {
    assert_eq!(MMIO_BASE, 0xFFFF_FF30_0000_0000);
    assert_eq!(MMIO_SIZE, 0x0000_0000_2000_0000); // 512 MiB
    assert!(MMIO_BASE > KVM_BASE);
}

#[test]
fn test_percpu_constants() {
    assert_eq!(PERCPU_BASE, 0xFFFF_FFC0_0000_0000);
    assert_eq!(PERCPU_STRIDE, 0x0000_0100_0000); // 16 MiB
    assert!(PERCPU_STRIDE % PAGE_SIZE_U64 == 0);
}

#[test]
fn test_stack_constants() {
    assert_eq!(KSTACK_SIZE, 64 * 1024);
    assert_eq!(IST_STACK_SIZE, 32 * 1024);
    assert_eq!(GUARD_PAGES, 1);
    assert_eq!(IST_STACKS_PER_CPU, 8);
}

#[test]
fn test_max_cpus_constant() {
    assert_eq!(MAX_CPUS, 64);
    assert!(MAX_CPUS > 0);
}

#[test]
fn test_permission_constants() {
    assert_eq!(PERM_READ, 1);
    assert_eq!(PERM_WRITE, 2);
    assert_eq!(PERM_EXEC, 4);
    // Ensure they're distinct bits
    assert_eq!(PERM_READ & PERM_WRITE, 0);
    assert_eq!(PERM_READ & PERM_EXEC, 0);
    assert_eq!(PERM_WRITE & PERM_EXEC, 0);
}

#[test]
fn test_selfref_slot_constant() {
    assert_eq!(SELFREF_SLOT, 510);
    assert!(SELFREF_SLOT < 512); // Must fit in PML4
}

#[test]
fn test_pcid_constants() {
    assert_eq!(PCID_KERNEL, 0x0001);
    assert_eq!(PCID_USER, 0x0002);
    assert_ne!(PCID_KERNEL, PCID_USER);
}

// ============================================================================
// ERROR TESTS
// ============================================================================

#[test]
fn test_error_display() {
    assert_eq!(LayoutError::SlideNotAligned.as_str(), "KASLR slide not page-aligned");
    assert_eq!(LayoutError::KernelBaseTooLow.as_str(), "Kernel base below higher-half");
    assert_eq!(LayoutError::WindowOverlap.as_str(), "Layout windows overlap");
    assert_eq!(LayoutError::NotInitialized.as_str(), "Layout not initialized");
}

#[test]
fn test_error_is_config_error() {
    assert!(LayoutError::SlideNotAligned.is_config_error());
    assert!(LayoutError::KernelBaseTooLow.is_config_error());
    assert!(LayoutError::PercpuStrideMisaligned.is_config_error());
    assert!(LayoutError::InvalidAlignment.is_config_error());
    assert!(LayoutError::InvalidRegionBounds.is_config_error());

    assert!(!LayoutError::WindowOverlap.is_config_error());
    assert!(!LayoutError::NotInitialized.is_config_error());
    assert!(!LayoutError::SizeExceedsCapacity.is_config_error());
}

#[test]
fn test_error_from_string() {
    let err: LayoutError = "slide not page-aligned".into();
    assert_eq!(err, LayoutError::SlideNotAligned);

    let err: LayoutError = "kernel base below higher-half".into();
    assert_eq!(err, LayoutError::KernelBaseTooLow);

    let err: LayoutError = "layout window overlap".into();
    assert_eq!(err, LayoutError::WindowOverlap);
}

// ============================================================================
// ALIGNMENT UTILITY TESTS
// ============================================================================

#[test]
fn test_align_down_basic() {
    assert_eq!(align_down(4096, 4096), 4096);
    assert_eq!(align_down(4097, 4096), 4096);
    assert_eq!(align_down(8191, 4096), 4096);
    assert_eq!(align_down(8192, 4096), 8192);
}

#[test]
fn test_align_down_zero() {
    assert_eq!(align_down(0, 4096), 0);
    assert_eq!(align_down(100, 4096), 0);
}

#[test]
fn test_align_down_invalid_alignment() {
    // Zero alignment returns input unchanged
    assert_eq!(align_down(1234, 0), 1234);
    // Non-power-of-two returns input unchanged
    assert_eq!(align_down(1234, 3), 1234);
    assert_eq!(align_down(1234, 5), 1234);
}

#[test]
fn test_align_up_basic() {
    assert_eq!(align_up(4096, 4096), 4096);
    assert_eq!(align_up(4097, 4096), 8192);
    assert_eq!(align_up(1, 4096), 4096);
    assert_eq!(align_up(0, 4096), 0);
}

#[test]
fn test_align_up_already_aligned() {
    assert_eq!(align_up(0, 4096), 0);
    assert_eq!(align_up(4096, 4096), 4096);
    assert_eq!(align_up(8192, 4096), 8192);
}

#[test]
fn test_align_up_invalid_alignment() {
    assert_eq!(align_up(1234, 0), 1234);
    assert_eq!(align_up(1234, 3), 1234);
}

#[test]
fn test_is_aligned() {
    assert!(is_aligned(0, 4096));
    assert!(is_aligned(4096, 4096));
    assert!(is_aligned(8192, 4096));
    assert!(!is_aligned(1, 4096));
    assert!(!is_aligned(4097, 4096));
}

#[test]
fn test_is_aligned_edge_cases() {
    // Zero alignment always returns false
    assert!(!is_aligned(0, 0));
    assert!(!is_aligned(4096, 0));

    // Everything is 1-aligned
    assert!(is_aligned(0, 1));
    assert!(is_aligned(12345, 1));
}

#[test]
fn test_is_page_aligned() {
    assert!(is_page_aligned(0));
    assert!(is_page_aligned(PAGE_SIZE_U64));
    assert!(is_page_aligned(PAGE_SIZE_U64 * 2));
    assert!(!is_page_aligned(1));
    assert!(!is_page_aligned(PAGE_SIZE_U64 + 1));
}

// ============================================================================
// ADDRESS SPACE TESTS
// ============================================================================

#[test]
fn test_in_kernel_space() {
    assert!(in_kernel_space(CANONICAL_HIGH_MIN));
    assert!(in_kernel_space(KERNEL_BASE));
    assert!(in_kernel_space(0xFFFF_FFFF_FFFF_FFFF));
    assert!(!in_kernel_space(0));
    assert!(!in_kernel_space(USER_TOP));
}

#[test]
fn test_in_user_space() {
    assert!(in_user_space(0));
    assert!(in_user_space(USER_TOP));
    assert!(in_user_space(0x1000));
    assert!(!in_user_space(CANONICAL_HIGH_MIN));
    assert!(!in_user_space(KERNEL_BASE));
}

#[test]
fn test_is_canonical() {
    // User space is canonical
    assert!(is_canonical(0));
    assert!(is_canonical(USER_TOP));

    // Kernel space is canonical
    assert!(is_canonical(CANONICAL_HIGH_MIN));
    assert!(is_canonical(KERNEL_BASE));

    // The hole is non-canonical
    assert!(!is_canonical(USER_TOP + 1));
    assert!(!is_canonical(CANONICAL_HIGH_MIN - 1));
    assert!(!is_canonical(0x0000_8000_0000_0000));
}

#[test]
fn test_range_function() {
    let r = range(0x1000, 0x2000);
    assert_eq!(r.start, 0x1000);
    assert_eq!(r.end, 0x3000);

    // Test saturating behavior
    let r = range(u64::MAX - 10, 100);
    assert_eq!(r.end, u64::MAX);
}

#[test]
fn test_selfref_l4_va() {
    let va = selfref_l4_va();
    // Should be in kernel space
    assert!(in_kernel_space(va));
    // Should be canonical
    assert!(is_canonical(va));
}

// ============================================================================
// SECTION TESTS
// ============================================================================

#[test]
fn test_section_new() {
    let section = Section::new(0x1000, 0x2000, true, false, false, true);
    assert_eq!(section.start, 0x1000);
    assert_eq!(section.end, 0x2000);
    assert!(section.rx);
    assert!(!section.rw);
    assert!(!section.nx);
    assert!(section.global);
}

#[test]
fn test_section_size() {
    let section = Section::new(0x1000, 0x2000, true, false, false, true);
    assert_eq!(section.size(), 0x1000);

    let empty = Section::new(0x2000, 0x1000, true, false, false, true);
    assert_eq!(empty.size(), 0);
}

#[test]
fn test_section_page_count() {
    let section = Section::new(0, PAGE_SIZE_U64 * 4, true, false, false, true);
    assert_eq!(section.page_count(), 4);

    // Partial page rounds up
    let section = Section::new(0, PAGE_SIZE_U64 + 1, true, false, false, true);
    assert_eq!(section.page_count(), 2);
}

#[test]
fn test_section_is_empty() {
    let empty1 = Section::new(0x1000, 0x1000, true, false, false, true);
    assert!(empty1.is_empty());

    let empty2 = Section::new(0x2000, 0x1000, true, false, false, true);
    assert!(empty2.is_empty());

    let valid = Section::new(0x1000, 0x2000, true, false, false, true);
    assert!(!valid.is_empty());
}

#[test]
fn test_section_contains() {
    let section = Section::new(0x1000, 0x2000, true, false, false, true);

    assert!(section.contains(0x1000)); // Start inclusive
    assert!(section.contains(0x1500));
    assert!(section.contains(0x1FFF));

    assert!(!section.contains(0x0FFF)); // Below
    assert!(!section.contains(0x2000)); // End exclusive
    assert!(!section.contains(0x3000)); // Above
}

// ============================================================================
// REGION KIND TESTS
// ============================================================================

#[test]
fn test_region_kind_is_usable() {
    assert!(RegionKind::Available.is_usable());
    assert!(RegionKind::Usable.is_usable());
    assert!(!RegionKind::Reserved.is_usable());
    assert!(!RegionKind::Acpi.is_usable());
    assert!(!RegionKind::Mmio.is_usable());
    assert!(!RegionKind::Kernel.is_usable());
    assert!(!RegionKind::Boot.is_usable());
    assert!(!RegionKind::Unknown.is_usable());
}

#[test]
fn test_region_kind_as_str() {
    assert_eq!(RegionKind::Available.as_str(), "Available");
    assert_eq!(RegionKind::Usable.as_str(), "Usable");
    assert_eq!(RegionKind::Reserved.as_str(), "Reserved");
    assert_eq!(RegionKind::Acpi.as_str(), "ACPI");
    assert_eq!(RegionKind::Mmio.as_str(), "MMIO");
    assert_eq!(RegionKind::Unknown.as_str(), "Unknown");
}

// ============================================================================
// REGION TESTS
// ============================================================================

#[test]
fn test_region_new() {
    let region = Region::new(0x1000, 0x10000, RegionKind::Usable);
    assert_eq!(region.start, 0x1000);
    assert_eq!(region.end, 0x10000);
    assert_eq!(region.kind, RegionKind::Usable);
}

#[test]
fn test_region_len() {
    let region = Region::new(0x1000, 0x10000, RegionKind::Usable);
    assert_eq!(region.len(), 0xF000);

    let empty = Region::new(0x1000, 0x1000, RegionKind::Usable);
    assert_eq!(empty.len(), 0);
}

#[test]
fn test_region_is_empty() {
    let empty = Region::new(0x1000, 0x1000, RegionKind::Usable);
    assert!(empty.is_empty());

    let valid = Region::new(0x1000, 0x2000, RegionKind::Usable);
    assert!(!valid.is_empty());
}

#[test]
fn test_region_is_usable() {
    let usable = Region::new(0, 0x1000, RegionKind::Usable);
    assert!(usable.is_usable());

    let available = Region::new(0, 0x1000, RegionKind::Available);
    assert!(available.is_usable());

    let reserved = Region::new(0, 0x1000, RegionKind::Reserved);
    assert!(!reserved.is_usable());
}

#[test]
fn test_region_page_count() {
    let region = Region::new(0, PAGE_SIZE_U64 * 10, RegionKind::Usable);
    assert_eq!(region.page_count(), 10);
}

#[test]
fn test_region_contains() {
    let region = Region::new(0x1000, 0x10000, RegionKind::Usable);

    assert!(region.contains(0x1000));
    assert!(region.contains(0x5000));
    assert!(region.contains(0xFFFF));

    assert!(!region.contains(0x0FFF));
    assert!(!region.contains(0x10000));
}

#[test]
fn test_region_from_firmware() {
    let usable = region_from_firmware(FIRMWARE_REGION_USABLE, 0x1000, 0x1000);
    assert_eq!(usable.kind, RegionKind::Usable);
    assert_eq!(usable.start, 0x1000);
    assert_eq!(usable.end, 0x2000);

    let reserved = region_from_firmware(FIRMWARE_REGION_RESERVED, 0, 0x1000);
    assert_eq!(reserved.kind, RegionKind::Reserved);

    let acpi = region_from_firmware(FIRMWARE_REGION_ACPI_RECLAIM, 0, 0x1000);
    assert_eq!(acpi.kind, RegionKind::Acpi);

    let mmio = region_from_firmware(FIRMWARE_REGION_MMIO, 0, 0x1000);
    assert_eq!(mmio.kind, RegionKind::Mmio);

    let unknown = region_from_firmware(99, 0, 0x1000);
    assert_eq!(unknown.kind, RegionKind::Unknown);
}

// ============================================================================
// MANAGED SPAN TESTS
// ============================================================================

#[test]
fn test_managed_span_single_region() {
    let regions = [Region::new(0x1000, 0x10000, RegionKind::Usable)];
    let (lo, hi) = managed_span(&regions);

    assert_eq!(lo, align_up(0x1000, PAGE_SIZE_U64));
    assert_eq!(hi, align_down(0x10000, PAGE_SIZE_U64));
}

#[test]
fn test_managed_span_multiple_regions() {
    let regions = [
        Region::new(0x1000, 0x10000, RegionKind::Usable),
        Region::new(0x20000, 0x30000, RegionKind::Usable),
        Region::new(0x50000, 0x60000, RegionKind::Reserved), // Not usable
    ];
    let (lo, hi) = managed_span(&regions);

    assert_eq!(lo, align_up(0x1000, PAGE_SIZE_U64));
    assert_eq!(hi, align_down(0x30000, PAGE_SIZE_U64));
}

#[test]
fn test_managed_span_no_usable() {
    let regions = [
        Region::new(0x1000, 0x10000, RegionKind::Reserved),
        Region::new(0x20000, 0x30000, RegionKind::Mmio),
    ];
    let (lo, hi) = managed_span(&regions);

    assert_eq!(lo, 0);
    assert_eq!(hi, 0);
}

#[test]
fn test_managed_span_empty() {
    let regions: &[Region] = &[];
    let (lo, hi) = managed_span(regions);

    assert_eq!(lo, 0);
    assert_eq!(hi, 0);
}

// ============================================================================
// STACK REGION TESTS
// ============================================================================

#[test]
fn test_stack_region_new() {
    let stack = StackRegion::new(0x1000, KSTACK_SIZE, GUARD_PAGES * PAGE_SIZE);
    assert_eq!(stack.base, 0x1000);
    assert_eq!(stack.size, KSTACK_SIZE);
    assert_eq!(stack.guard_size, GUARD_PAGES * PAGE_SIZE);
    assert!(stack.cpu_id.is_none());
    assert!(stack.thread_id.is_none());
}

#[test]
fn test_stack_region_per_cpu() {
    let stack = StackRegion::per_cpu(0x1000, KSTACK_SIZE, PAGE_SIZE, 3);
    assert_eq!(stack.cpu_id, Some(3));
    assert!(stack.thread_id.is_none());
}

#[test]
fn test_stack_region_total_size() {
    let stack = StackRegion::new(0x1000, KSTACK_SIZE, PAGE_SIZE);
    assert_eq!(stack.total_size(), KSTACK_SIZE + PAGE_SIZE);
}

#[test]
fn test_stack_region_stack_top() {
    let stack = StackRegion::new(0x1000, KSTACK_SIZE, PAGE_SIZE);
    assert_eq!(stack.stack_top(), 0x1000 + KSTACK_SIZE as u64);
}

// ============================================================================
// PERCPU REGION TESTS
// ============================================================================

#[test]
fn test_percpu_region_new() {
    let region = PercpuRegion::new(PERCPU_BASE, PERCPU_STRIDE as usize, 0);
    assert_eq!(region.base, PERCPU_BASE);
    assert_eq!(region.size, PERCPU_STRIDE as usize);
    assert_eq!(region.cpu_id, 0);
}

#[test]
fn test_percpu_region_end() {
    let region = PercpuRegion::new(0x1000, 0x1000, 0);
    assert_eq!(region.end(), 0x2000);
}

#[test]
fn test_percpu_region_contains() {
    let region = PercpuRegion::new(0x1000, 0x1000, 0);
    assert!(region.contains(0x1000));
    assert!(region.contains(0x1500));
    assert!(!region.contains(0x2000));
}

// ============================================================================
// MODULE REGION TESTS
// ============================================================================

#[test]
fn test_module_region_new() {
    let module = ModuleRegion::new(0x1000, 0x1000, "test", PERM_READ | PERM_EXEC);
    assert_eq!(module.base, 0x1000);
    assert_eq!(module.size, 0x1000);
    assert_eq!(module.name, "test");
    assert_eq!(module.permissions, PERM_READ | PERM_EXEC);
}

#[test]
fn test_module_region_permissions() {
    let rx = ModuleRegion::new(0, 0x1000, "rx", PERM_READ | PERM_EXEC);
    assert!(rx.is_readable());
    assert!(!rx.is_writable());
    assert!(rx.is_executable());

    let rw = ModuleRegion::new(0, 0x1000, "rw", PERM_READ | PERM_WRITE);
    assert!(rw.is_readable());
    assert!(rw.is_writable());
    assert!(!rw.is_executable());

    let all = ModuleRegion::new(0, 0x1000, "rwx", PERM_READ | PERM_WRITE | PERM_EXEC);
    assert!(all.is_readable());
    assert!(all.is_writable());
    assert!(all.is_executable());
}

#[test]
fn test_module_region_end() {
    let module = ModuleRegion::new(0x1000, 0x1000, "test", 0);
    assert_eq!(module.end(), 0x2000);
}

// ============================================================================
// LAYOUT CONFIG TESTS
// ============================================================================

#[test]
fn test_layout_config_default() {
    let config = LayoutConfig::default();
    assert_eq!(config.slide, 0);
    assert_eq!(config.heap_lo, KHEAP_BASE);
    assert_eq!(config.heap_sz, KHEAP_SIZE);
    assert_eq!(config.vm_lo, KVM_BASE);
    assert_eq!(config.vm_sz, KVM_SIZE);
    assert_eq!(config.mmio_lo, MMIO_BASE);
    assert_eq!(config.mmio_sz, MMIO_SIZE);
    assert!(!config.initialized);
}

// ============================================================================
// KASLR SLIDE TESTS
// ============================================================================

#[test]
fn test_apply_kaslr_slide_aligned() {
    // Reset layout first
    {
        let mut layout = super::LAYOUT.write();
        *layout = LayoutConfig::default();
    }

    let slide = PAGE_SIZE_U64 * 256; // 1 MiB
    let result = apply_kaslr_slide(slide);
    assert!(result.is_ok());

    let layout = get_layout();
    assert_eq!(layout.slide, slide);
    assert_eq!(layout.heap_lo, KHEAP_BASE.wrapping_add(slide));
    assert_eq!(layout.vm_lo, KVM_BASE.wrapping_add(slide));
    assert_eq!(layout.mmio_lo, MMIO_BASE.wrapping_add(slide));
    assert!(layout.initialized);
}

#[test]
fn test_apply_kaslr_slide_unaligned() {
    let result = apply_kaslr_slide(4097); // Not page-aligned
    assert_eq!(result, Err(LayoutError::SlideNotAligned));
}

#[test]
fn test_get_slide() {
    // Reset layout
    {
        let mut layout = super::LAYOUT.write();
        *layout = LayoutConfig::default();
    }

    assert_eq!(get_slide(), 0);

    let _ = apply_kaslr_slide(PAGE_SIZE_U64 * 100);
    assert_eq!(get_slide(), PAGE_SIZE_U64 * 100);
}

#[test]
fn test_slid_address() {
    // Reset layout
    {
        let mut layout = super::LAYOUT.write();
        layout.slide = PAGE_SIZE_U64 * 10;
    }

    let base = 0x1000u64;
    let slid = slid_address(base);
    assert_eq!(slid, base.wrapping_add(PAGE_SIZE_U64 * 10));
}

#[test]
fn test_slid_range() {
    // Reset layout
    {
        let mut layout = super::LAYOUT.write();
        layout.slide = PAGE_SIZE_U64;
    }

    let r = slid_range(0x1000, 0x2000);
    assert_eq!(r.start, 0x1000 + PAGE_SIZE_U64);
    assert_eq!(r.end, 0x1000 + PAGE_SIZE_U64 + 0x2000);
}

// ============================================================================
// LAYOUT VALIDATION TESTS
// ============================================================================

#[test]
fn test_validate_layout_default() {
    // Reset to default layout
    {
        let mut layout = super::LAYOUT.write();
        *layout = LayoutConfig::default();
    }

    // Default layout should be valid
    let result = validate_layout();
    assert!(result.is_ok());
}

// ============================================================================
// VM WINDOW TESTS
// ============================================================================

#[test]
fn test_vm_window() {
    {
        let mut layout = super::LAYOUT.write();
        *layout = LayoutConfig::default();
    }

    let (base, size) = vm_window();
    assert_eq!(base, KVM_BASE);
    assert_eq!(size, KVM_SIZE);
}

#[test]
fn test_mmio_window() {
    {
        let mut layout = super::LAYOUT.write();
        *layout = LayoutConfig::default();
    }

    let (base, size) = mmio_window();
    assert_eq!(base, MMIO_BASE);
    assert_eq!(size, MMIO_SIZE);
}

// ============================================================================
// STACK REGION RETRIEVAL TESTS
// ============================================================================

#[test]
fn test_get_all_stack_regions_count() {
    let regions = get_all_stack_regions();

    // Each CPU should have 1 main stack + 8 IST stacks = 9 stacks
    let expected_count = (MAX_CPUS as usize) * (1 + IST_STACKS_PER_CPU);
    assert_eq!(regions.len(), expected_count);
}

#[test]
fn test_get_all_stack_regions_cpu_ids() {
    let regions = get_all_stack_regions();

    // All regions should have a CPU ID
    for region in &regions {
        assert!(region.cpu_id.is_some());
        assert!(region.cpu_id.unwrap() < MAX_CPUS);
    }
}

// ============================================================================
// PERCPU REGION RETRIEVAL TESTS
// ============================================================================

#[test]
fn test_get_percpu_regions_count() {
    let regions = get_percpu_regions();
    assert_eq!(regions.len(), MAX_CPUS as usize);
}

#[test]
fn test_get_percpu_regions_ordering() {
    let regions = get_percpu_regions();

    for (i, region) in regions.iter().enumerate() {
        assert_eq!(region.cpu_id, i as u32);
        assert_eq!(region.base, PERCPU_BASE + (i as u64) * PERCPU_STRIDE);
    }
}

#[test]
fn test_get_percpu_region_for_valid() {
    let region = get_percpu_region_for(5);
    assert!(region.is_some());

    let region = region.unwrap();
    assert_eq!(region.cpu_id, 5);
    assert_eq!(region.base, PERCPU_BASE + 5 * PERCPU_STRIDE);
}

#[test]
fn test_get_percpu_region_for_invalid() {
    let region = get_percpu_region_for(MAX_CPUS);
    assert!(region.is_none());

    let region = get_percpu_region_for(MAX_CPUS + 100);
    assert!(region.is_none());
}

// ============================================================================
// IS_INITIALIZED TESTS
// ============================================================================

#[test]
fn test_is_initialized() {
    {
        let mut layout = super::LAYOUT.write();
        layout.initialized = false;
    }
    assert!(!is_initialized());

    {
        let mut layout = super::LAYOUT.write();
        layout.initialized = true;
    }
    assert!(is_initialized());
}

// ============================================================================
// LAYOUT SUMMARY TESTS
// ============================================================================

#[test]
fn test_layout_summary_format() {
    {
        let mut layout = super::LAYOUT.write();
        *layout = LayoutConfig::default();
    }

    let summary = layout_summary();
    assert!(summary.contains("Layout"));
    assert!(summary.contains("slide"));
    assert!(summary.contains("heap"));
    assert!(summary.contains("vm"));
    assert!(summary.contains("mmio"));
}
