use crate::process::address_space::*;
use x86_64::VirtAddr;

#[test]
fn page_size_constant() {
    assert_eq!(PAGE_SIZE, 4096);
}

#[test]
fn large_page_size_constant() {
    assert_eq!(LARGE_PAGE_SIZE, 2 * 1024 * 1024);
}

#[test]
fn huge_page_size_constant() {
    assert_eq!(HUGE_PAGE_SIZE, 1024 * 1024 * 1024);
}

#[test]
fn user_space_end_constant() {
    assert_eq!(USER_SPACE_END, 0x0000_8000_0000_0000);
}

#[test]
fn kernel_space_start_constant() {
    assert_eq!(KERNEL_SPACE_START, 0xFFFF_8000_0000_0000);
}

#[test]
fn max_pcid_constant() {
    assert_eq!(MAX_PCID, 4096);
}

#[test]
fn vma_new() {
    let prot = ProtectionFlags::new(true, true, false, true);
    let vma = Vma::new(
        VirtAddr::new(0x1000),
        VirtAddr::new(0x2000),
        prot,
    );
    assert_eq!(vma.start.as_u64(), 0x1000);
    assert_eq!(vma.end.as_u64(), 0x2000);
    assert!(!vma.cow);
    assert!(vma.anonymous);
    assert_eq!(vma.refcount, 1);
}

#[test]
fn vma_size() {
    let prot = ProtectionFlags::new(true, false, false, true);
    let vma = Vma::new(
        VirtAddr::new(0x1000),
        VirtAddr::new(0x5000),
        prot,
    );
    assert_eq!(vma.size(), 0x4000);
}

#[test]
fn vma_contains() {
    let prot = ProtectionFlags::new(true, false, false, true);
    let vma = Vma::new(
        VirtAddr::new(0x1000),
        VirtAddr::new(0x2000),
        prot,
    );
    assert!(vma.contains(VirtAddr::new(0x1000)));
    assert!(vma.contains(VirtAddr::new(0x1500)));
    assert!(vma.contains(VirtAddr::new(0x1FFF)));
    assert!(!vma.contains(VirtAddr::new(0x2000)));
    assert!(!vma.contains(VirtAddr::new(0x0FFF)));
}

#[test]
fn vma_overlaps() {
    let prot = ProtectionFlags::new(true, false, false, true);
    let vma1 = Vma::new(
        VirtAddr::new(0x1000),
        VirtAddr::new(0x2000),
        prot,
    );
    let vma2 = Vma::new(
        VirtAddr::new(0x1500),
        VirtAddr::new(0x2500),
        prot,
    );
    let vma3 = Vma::new(
        VirtAddr::new(0x2000),
        VirtAddr::new(0x3000),
        prot,
    );
    assert!(vma1.overlaps(&vma2));
    assert!(vma2.overlaps(&vma1));
    assert!(!vma1.overlaps(&vma3));
    assert!(!vma3.overlaps(&vma1));
}

#[test]
fn vma_overlaps_subset() {
    let prot = ProtectionFlags::new(true, false, false, true);
    let outer = Vma::new(
        VirtAddr::new(0x1000),
        VirtAddr::new(0x5000),
        prot,
    );
    let inner = Vma::new(
        VirtAddr::new(0x2000),
        VirtAddr::new(0x3000),
        prot,
    );
    assert!(outer.overlaps(&inner));
    assert!(inner.overlaps(&outer));
}

#[test]
fn vma_clone() {
    let prot = ProtectionFlags::new(true, true, false, true);
    let vma1 = Vma {
        start: VirtAddr::new(0x1000),
        end: VirtAddr::new(0x2000),
        prot,
        cow: true,
        anonymous: false,
        refcount: 5,
    };
    let vma2 = vma1.clone();
    assert_eq!(vma1.start, vma2.start);
    assert_eq!(vma1.end, vma2.end);
    assert_eq!(vma1.prot, vma2.prot);
    assert_eq!(vma1.cow, vma2.cow);
    assert_eq!(vma1.anonymous, vma2.anonymous);
    assert_eq!(vma1.refcount, vma2.refcount);
}

#[test]
fn protection_flags_read_only() {
    let prot = ProtectionFlags::new(true, false, false, false);
    assert!(prot.read);
    assert!(!prot.write);
    assert!(!prot.execute);
}

#[test]
fn protection_flags_write() {
    let prot = ProtectionFlags::new(false, true, false, false);
    assert!(!prot.read);
    assert!(prot.write);
    assert!(!prot.execute);
}

#[test]
fn protection_flags_exec() {
    let prot = ProtectionFlags::new(false, false, true, false);
    assert!(!prot.read);
    assert!(!prot.write);
    assert!(prot.execute);
}

#[test]
fn protection_flags_combined() {
    let prot = ProtectionFlags::new(true, true, false, true);
    assert!(prot.read);
    assert!(prot.write);
    assert!(!prot.execute);
    assert!(prot.user);
}

#[test]
fn protection_flags_all() {
    let prot = ProtectionFlags::new(true, true, true, true);
    assert!(prot.read);
    assert!(prot.write);
    assert!(prot.execute);
    assert!(prot.user);
}

#[test]
fn pte_flags_addr_mask() {
    assert_eq!(pte_flags::ADDR_MASK, 0x000F_FFFF_FFFF_F000);
}

#[test]
fn address_space_boundaries() {
    assert!(USER_SPACE_END < KERNEL_SPACE_START);
}

#[test]
fn page_sizes_ordering() {
    assert!(PAGE_SIZE < LARGE_PAGE_SIZE);
    assert!(LARGE_PAGE_SIZE < HUGE_PAGE_SIZE);
}

#[test]
fn page_sizes_power_of_two() {
    assert!(PAGE_SIZE.is_power_of_two());
    assert!(LARGE_PAGE_SIZE.is_power_of_two());
    assert!(HUGE_PAGE_SIZE.is_power_of_two());
}

#[test]
fn page_size_alignment() {
    assert_eq!(LARGE_PAGE_SIZE % PAGE_SIZE, 0);
    assert_eq!(HUGE_PAGE_SIZE % LARGE_PAGE_SIZE, 0);
}

#[test]
fn vma_size_zero() {
    let prot = ProtectionFlags::new(true, false, false, true);
    let vma = Vma::new(
        VirtAddr::new(0x1000),
        VirtAddr::new(0x1000),
        prot,
    );
    assert_eq!(vma.size(), 0);
}

#[test]
fn vma_adjacent_not_overlapping() {
    let prot = ProtectionFlags::new(true, false, false, true);
    let vma1 = Vma::new(
        VirtAddr::new(0x1000),
        VirtAddr::new(0x2000),
        prot,
    );
    let vma2 = Vma::new(
        VirtAddr::new(0x2000),
        VirtAddr::new(0x3000),
        prot,
    );
    assert!(!vma1.overlaps(&vma2));
}

#[test]
fn vma_cow_flag() {
    let prot = ProtectionFlags::new(true, true, false, true);
    let mut vma = Vma::new(
        VirtAddr::new(0x1000),
        VirtAddr::new(0x2000),
        prot,
    );
    assert!(!vma.cow);
    vma.cow = true;
    assert!(vma.cow);
}

#[test]
fn vma_anonymous_flag() {
    let prot = ProtectionFlags::new(true, false, false, true);
    let mut vma = Vma::new(
        VirtAddr::new(0x1000),
        VirtAddr::new(0x2000),
        prot,
    );
    assert!(vma.anonymous);
    vma.anonymous = false;
    assert!(!vma.anonymous);
}

#[test]
fn vma_refcount_increment() {
    let prot = ProtectionFlags::new(true, false, false, true);
    let mut vma = Vma::new(
        VirtAddr::new(0x1000),
        VirtAddr::new(0x2000),
        prot,
    );
    assert_eq!(vma.refcount, 1);
    vma.refcount += 1;
    assert_eq!(vma.refcount, 2);
}

#[test]
fn protection_flags_default() {
    let prot = ProtectionFlags::default();
    assert!(prot.read);
    assert!(!prot.write);
    assert!(!prot.execute);
    assert!(prot.user);
}

#[test]
fn protection_flags_equality() {
    let prot1 = ProtectionFlags::new(true, true, false, true);
    let prot2 = ProtectionFlags::new(true, true, false, true);
    let prot3 = ProtectionFlags::new(true, false, false, true);
    assert_eq!(prot1, prot2);
    assert_ne!(prot1, prot3);
}

#[test]
fn protection_flags_to_pte_flags() {
    let prot = ProtectionFlags::new(true, true, true, true);
    let flags = prot.to_pte_flags();
    assert!(flags & pte_flags::PRESENT != 0);
    assert!(flags & pte_flags::WRITABLE != 0);
    assert!(flags & pte_flags::USER_ACCESSIBLE != 0);
    assert!(flags & pte_flags::NO_EXECUTE == 0);
}

#[test]
fn protection_flags_no_exec_flag() {
    let prot = ProtectionFlags::new(true, false, false, true);
    let flags = prot.to_pte_flags();
    assert!(flags & pte_flags::NO_EXECUTE != 0);
}
