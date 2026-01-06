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
// ============================================================================
// CONSTANT TESTS
// ============================================================================
#[test]
fn test_pte_bits() {
    assert_eq!(PTE_PRESENT, 1 << 0);
    assert_eq!(PTE_WRITABLE, 1 << 1);
    assert_eq!(PTE_USER, 1 << 2);
    assert_eq!(PTE_WRITE_THROUGH, 1 << 3);
    assert_eq!(PTE_CACHE_DISABLE, 1 << 4);
    assert_eq!(PTE_ACCESSED, 1 << 5);
    assert_eq!(PTE_DIRTY, 1 << 6);
    assert_eq!(PTE_HUGE_PAGE, 1 << 7);
    assert_eq!(PTE_GLOBAL, 1 << 8);
    assert_eq!(PTE_NO_EXECUTE, 1u64 << 63);
}

#[test]
fn test_cr4_bits() {
    assert_eq!(CR4_PGE, 1 << 7);
    assert_eq!(CR4_SMEP, 1 << 20);
    assert_eq!(CR4_SMAP, 1 << 21);
}

#[test]
fn test_cpuid_constants() {
    assert_eq!(CPUID_FEATURES_LEAF, 0x07);
    assert_eq!(CPUID_EBX_SMEP, 1 << 7);
    assert_eq!(CPUID_EBX_SMAP, 1 << 20);
    assert_eq!(CPUID_EXTENDED_LEAF, 0x8000_0001);
    assert_eq!(CPUID_EDX_NX, 1 << 20);
}

#[test]
fn test_msr_constants() {
    assert_eq!(MSR_IA32_EFER, 0xC000_0080);
    assert_eq!(EFER_NXE, 1 << 11);
}

#[test]
fn test_page_table_constants() {
    assert_eq!(PAGE_TABLE_ENTRIES, 512);
    assert_eq!(PAGE_SIZE, 4096);
}
// ============================================================================
// INDEX EXTRACTION TESTS
// ============================================================================
#[test]
fn test_pml4_index() {
    assert_eq!(pml4_index(0), 0);
    assert_eq!(pml4_index(256u64 << 39), 256);
    assert_eq!(pml4_index(511u64 << 39), 511);
}

#[test]
fn test_pdpt_index() {
    assert_eq!(pdpt_index(0), 0);
    assert_eq!(pdpt_index(100u64 << 30), 100);
    assert_eq!(pdpt_index(511u64 << 30), 511);
}

#[test]
fn test_pd_index() {
    assert_eq!(pd_index(0), 0);
    assert_eq!(pd_index(200u64 << 21), 200);
    assert_eq!(pd_index(511u64 << 21), 511);
}

#[test]
fn test_pt_index() {
    assert_eq!(pt_index(0), 0);
    assert_eq!(pt_index(300u64 << 12), 300);
    assert_eq!(pt_index(511u64 << 12), 511);
}

#[test]
fn test_pte_is_present() {
    assert!(pte_is_present(PTE_PRESENT));
    assert!(pte_is_present(PTE_PRESENT | PTE_WRITABLE));
    assert!(!pte_is_present(0));
    assert!(!pte_is_present(PTE_WRITABLE)); // Writable but not present
}

#[test]
fn test_pte_address() {
    let pte = 0x1234_5000 | PTE_PRESENT | PTE_WRITABLE;
    assert_eq!(pte_address(pte), 0x1234_5000);

    let pte_with_nx = 0x1234_5000 | PTE_PRESENT | PTE_NO_EXECUTE;
    assert_eq!(pte_address(pte_with_nx), 0x1234_5000);
}
// ============================================================================
// PROTECTION FLAGS TESTS
// ============================================================================
#[test]
fn test_protection_flags_new() {
    let flags = ProtectionFlags::new();
    assert!(!flags.smep_enabled);
    assert!(!flags.smap_enabled);
    assert!(!flags.nx_enabled);
    assert!(flags.wp_enabled);
}

#[test]
fn test_protection_flags_fully_protected() {
    let flags = ProtectionFlags {
        smep_enabled: true,
        smap_enabled: true,
        nx_enabled: true,
        wp_enabled: true,
    };
    assert!(flags.is_fully_protected());

    let partial = ProtectionFlags {
        smep_enabled: true,
        smap_enabled: false,
        nx_enabled: true,
        wp_enabled: true,
    };
    assert!(!partial.is_fully_protected());
}

// ============================================================================
// PAGE TABLE ENTRY TESTS
// ============================================================================

#[test]
fn test_pte_empty() {
    let pte = PageTableEntry::empty();
    assert!(!pte.present);
    assert!(!pte.writable);
    assert_eq!(pte.physical_address, 0);
}

#[test]
fn test_pte_from_raw() {
    let raw = 0x1000 | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
    let pte = PageTableEntry::from_raw(raw);
    assert!(pte.present);
    assert!(pte.writable);
    assert!(pte.user_accessible);
    assert!(!pte.no_execute);
    assert_eq!(pte.physical_address, 0x1000);
}

#[test]
fn test_pte_to_raw() {
    let pte = PageTableEntry {
        present: true,
        writable: true,
        user_accessible: false,
        write_through: false,
        cache_disabled: false,
        accessed: false,
        dirty: false,
        huge_page: false,
        global: false,
        no_execute: true,
        physical_address: 0x2000,
    };

    let raw = pte.to_raw();
    assert!(raw & PTE_PRESENT != 0);
    assert!(raw & PTE_WRITABLE != 0);
    assert!(raw & PTE_USER == 0);
    assert!(raw & PTE_NO_EXECUTE != 0);
    assert_eq!(raw & PTE_ADDR_MASK, 0x2000);
}

#[test]
fn test_pte_roundtrip() {
    let original = PageTableEntry {
        present: true,
        writable: true,
        user_accessible: true,
        write_through: true,
        cache_disabled: true,
        accessed: true,
        dirty: true,
        huge_page: false,
        global: true,
        no_execute: true,
        physical_address: 0x3000,
    };

    let raw = original.to_raw();
    let decoded = PageTableEntry::from_raw(raw);

    assert_eq!(decoded.present, original.present);
    assert_eq!(decoded.writable, original.writable);
    assert_eq!(decoded.user_accessible, original.user_accessible);
    assert_eq!(decoded.no_execute, original.no_execute);
    assert_eq!(decoded.physical_address, original.physical_address);
}

#[test]
fn test_pte_wx_violation() {
    let safe = PageTableEntry {
        present: true,
        writable: true,
        no_execute: true, // NX set = not executable
        ..PageTableEntry::empty()
    };
    assert!(!safe.is_wx_violation());

    let violation = PageTableEntry {
        present: true,
        writable: true,
        no_execute: false, // NX not set = executable
        ..PageTableEntry::empty()
    };
    assert!(violation.is_wx_violation());
}
// ============================================================================
// PAGE PERMISSIONS TESTS
// ============================================================================
#[test]
fn test_permissions_kernel_ro() {
    let perms = PagePermissions::kernel_ro();
    assert!(!perms.writable);
    assert!(!perms.user_accessible);
    assert!(!perms.executable);
    assert!(!perms.cache_disabled);
}

#[test]
fn test_permissions_kernel_rw() {
    let perms = PagePermissions::kernel_rw();
    assert!(perms.writable);
    assert!(!perms.executable);
}

#[test]
fn test_permissions_kernel_rx() {
    let perms = PagePermissions::kernel_rx();
    assert!(!perms.writable);
    assert!(perms.executable);
}

#[test]
fn test_permissions_device() {
    let perms = PagePermissions::device();
    assert!(perms.writable);
    assert!(!perms.executable);
    assert!(perms.cache_disabled);
}

#[test]
fn test_permissions_wx_violation() {
    let safe_rw = PagePermissions::kernel_rw();
    assert!(!safe_rw.is_wx_violation());

    let safe_rx = PagePermissions::kernel_rx();
    assert!(!safe_rx.is_wx_violation());

    let violation = PagePermissions {
        writable: true,
        executable: true,
        user_accessible: false,
        cache_disabled: false,
    };
    assert!(violation.is_wx_violation());
}

#[test]
fn test_permissions_to_pte() {
    let perms = PagePermissions::kernel_rw();
    let pte = perms.to_pte(0x4000);

    assert!(pte.present);
    assert!(pte.writable);
    assert!(!pte.user_accessible);
    assert!(pte.no_execute);
    assert_eq!(pte.physical_address, 0x4000);
}
// ============================================================================
// ERROR TESTS
// ============================================================================
#[test]
fn test_mmu_error_as_str() {
    assert_eq!(MmuError::NotInitialized.as_str(), "MMU not initialized");
    assert_eq!(MmuError::NxNotSupported.as_str(), "NXE not supported by CPU");
    assert_eq!(MmuError::WXViolation.as_str(), "W^X violation: requested RW+X");
}

#[test]
fn test_mmu_error_is_fatal() {
    assert!(MmuError::NxNotSupported.is_fatal());
    assert!(MmuError::FrameAllocationFailed.is_fatal());
    assert!(MmuError::NoPageTableLoaded.is_fatal());
    assert!(!MmuError::NotMapped.is_fatal());
}

#[test]
fn test_mmu_error_is_security_violation() {
    assert!(MmuError::WXViolation.is_security_violation());
    assert!(!MmuError::NotInitialized.is_security_violation());
}

#[test]
fn test_mmu_error_display() {
    let error = MmuError::NotMapped;
    let msg = format!("{}", error);
    assert_eq!(msg, "Not mapped");
}

#[test]
fn test_mmu_error_from_str() {
    assert_eq!(
        MmuError::from("MMU not initialized"),
        MmuError::NotInitialized
    );
    assert_eq!(
        MmuError::from("W^X violation: requested RW+X"),
        MmuError::WXViolation
    );
    assert_eq!(
        MmuError::from("W^X violation: RW+X not allowed"),
        MmuError::WXViolation
    );
}
// ============================================================================
// MMU TESTS
// ============================================================================
#[test]
fn test_mmu_new() {
    let mmu = MMU::new();
    assert!(!mmu.is_initialized());
    assert_eq!(mmu.get_current_cr3(), 0);
}
