use crate::memory::addr::VirtAddr;
use crate::process::address_space::*;
use crate::test::framework::TestResult;

pub(crate) fn test_page_size_constant() -> TestResult {
    if PAGE_SIZE != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_large_page_size_constant() -> TestResult {
    if LARGE_PAGE_SIZE != 2 * 1024 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_huge_page_size_constant() -> TestResult {
    if HUGE_PAGE_SIZE != 1024 * 1024 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_user_space_end_constant() -> TestResult {
    if USER_SPACE_END != 0x0000_8000_0000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kernel_space_start_constant() -> TestResult {
    if KERNEL_SPACE_START != 0xFFFF_8000_0000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_pcid_constant() -> TestResult {
    if MAX_PCID != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vma_new() -> TestResult {
    let prot = ProtectionFlags::new(true, true, false, true);
    let vma = Vma::new(VirtAddr::new(0x1000), VirtAddr::new(0x2000), prot);
    if vma.start.as_u64() != 0x1000 {
        return TestResult::Fail;
    }
    if vma.end.as_u64() != 0x2000 {
        return TestResult::Fail;
    }
    if vma.cow {
        return TestResult::Fail;
    }
    if !vma.anonymous {
        return TestResult::Fail;
    }
    if vma.refcount != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vma_size() -> TestResult {
    let prot = ProtectionFlags::new(true, false, false, true);
    let vma = Vma::new(VirtAddr::new(0x1000), VirtAddr::new(0x5000), prot);
    if vma.size() != 0x4000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vma_contains() -> TestResult {
    let prot = ProtectionFlags::new(true, false, false, true);
    let vma = Vma::new(VirtAddr::new(0x1000), VirtAddr::new(0x2000), prot);
    if !vma.contains(VirtAddr::new(0x1000)) {
        return TestResult::Fail;
    }
    if !vma.contains(VirtAddr::new(0x1500)) {
        return TestResult::Fail;
    }
    if !vma.contains(VirtAddr::new(0x1FFF)) {
        return TestResult::Fail;
    }
    if vma.contains(VirtAddr::new(0x2000)) {
        return TestResult::Fail;
    }
    if vma.contains(VirtAddr::new(0x0FFF)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vma_overlaps() -> TestResult {
    let prot = ProtectionFlags::new(true, false, false, true);
    let vma1 = Vma::new(VirtAddr::new(0x1000), VirtAddr::new(0x2000), prot);
    let vma2 = Vma::new(VirtAddr::new(0x1500), VirtAddr::new(0x2500), prot);
    let vma3 = Vma::new(VirtAddr::new(0x2000), VirtAddr::new(0x3000), prot);
    if !vma1.overlaps(&vma2) {
        return TestResult::Fail;
    }
    if !vma2.overlaps(&vma1) {
        return TestResult::Fail;
    }
    if vma1.overlaps(&vma3) {
        return TestResult::Fail;
    }
    if vma3.overlaps(&vma1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vma_overlaps_subset() -> TestResult {
    let prot = ProtectionFlags::new(true, false, false, true);
    let outer = Vma::new(VirtAddr::new(0x1000), VirtAddr::new(0x5000), prot);
    let inner = Vma::new(VirtAddr::new(0x2000), VirtAddr::new(0x3000), prot);
    if !outer.overlaps(&inner) {
        return TestResult::Fail;
    }
    if !inner.overlaps(&outer) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vma_clone() -> TestResult {
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
    if vma1.start != vma2.start {
        return TestResult::Fail;
    }
    if vma1.end != vma2.end {
        return TestResult::Fail;
    }
    if vma1.prot != vma2.prot {
        return TestResult::Fail;
    }
    if vma1.cow != vma2.cow {
        return TestResult::Fail;
    }
    if vma1.anonymous != vma2.anonymous {
        return TestResult::Fail;
    }
    if vma1.refcount != vma2.refcount {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_protection_flags_read_only() -> TestResult {
    let prot = ProtectionFlags::new(true, false, false, false);
    if !prot.read {
        return TestResult::Fail;
    }
    if prot.write {
        return TestResult::Fail;
    }
    if prot.execute {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_protection_flags_write() -> TestResult {
    let prot = ProtectionFlags::new(false, true, false, false);
    if prot.read {
        return TestResult::Fail;
    }
    if !prot.write {
        return TestResult::Fail;
    }
    if prot.execute {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_protection_flags_exec() -> TestResult {
    let prot = ProtectionFlags::new(false, false, true, false);
    if prot.read {
        return TestResult::Fail;
    }
    if prot.write {
        return TestResult::Fail;
    }
    if !prot.execute {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_protection_flags_combined() -> TestResult {
    let prot = ProtectionFlags::new(true, true, false, true);
    if !prot.read {
        return TestResult::Fail;
    }
    if !prot.write {
        return TestResult::Fail;
    }
    if prot.execute {
        return TestResult::Fail;
    }
    if !prot.user {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_protection_flags_all() -> TestResult {
    let prot = ProtectionFlags::new(true, true, true, true);
    if !prot.read {
        return TestResult::Fail;
    }
    if !prot.write {
        return TestResult::Fail;
    }
    if !prot.execute {
        return TestResult::Fail;
    }
    if !prot.user {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pte_flags_addr_mask() -> TestResult {
    if pte_flags::ADDR_MASK != 0x000F_FFFF_FFFF_F000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_address_space_boundaries() -> TestResult {
    if !(USER_SPACE_END < KERNEL_SPACE_START) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_sizes_ordering() -> TestResult {
    if !(PAGE_SIZE < LARGE_PAGE_SIZE) {
        return TestResult::Fail;
    }
    if !(LARGE_PAGE_SIZE < HUGE_PAGE_SIZE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_sizes_power_of_two() -> TestResult {
    if !PAGE_SIZE.is_power_of_two() {
        return TestResult::Fail;
    }
    if !LARGE_PAGE_SIZE.is_power_of_two() {
        return TestResult::Fail;
    }
    if !HUGE_PAGE_SIZE.is_power_of_two() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_alignment() -> TestResult {
    if LARGE_PAGE_SIZE % PAGE_SIZE != 0 {
        return TestResult::Fail;
    }
    if HUGE_PAGE_SIZE % LARGE_PAGE_SIZE != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vma_size_zero() -> TestResult {
    let prot = ProtectionFlags::new(true, false, false, true);
    let vma = Vma::new(VirtAddr::new(0x1000), VirtAddr::new(0x1000), prot);
    if vma.size() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vma_adjacent_not_overlapping() -> TestResult {
    let prot = ProtectionFlags::new(true, false, false, true);
    let vma1 = Vma::new(VirtAddr::new(0x1000), VirtAddr::new(0x2000), prot);
    let vma2 = Vma::new(VirtAddr::new(0x2000), VirtAddr::new(0x3000), prot);
    if vma1.overlaps(&vma2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vma_cow_flag() -> TestResult {
    let prot = ProtectionFlags::new(true, true, false, true);
    let mut vma = Vma::new(VirtAddr::new(0x1000), VirtAddr::new(0x2000), prot);
    if vma.cow {
        return TestResult::Fail;
    }
    vma.cow = true;
    if !vma.cow {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vma_anonymous_flag() -> TestResult {
    let prot = ProtectionFlags::new(true, false, false, true);
    let mut vma = Vma::new(VirtAddr::new(0x1000), VirtAddr::new(0x2000), prot);
    if !vma.anonymous {
        return TestResult::Fail;
    }
    vma.anonymous = false;
    if vma.anonymous {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vma_refcount_increment() -> TestResult {
    let prot = ProtectionFlags::new(true, false, false, true);
    let mut vma = Vma::new(VirtAddr::new(0x1000), VirtAddr::new(0x2000), prot);
    if vma.refcount != 1 {
        return TestResult::Fail;
    }
    vma.refcount += 1;
    if vma.refcount != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_protection_flags_default() -> TestResult {
    let prot = ProtectionFlags::default();
    if !prot.read {
        return TestResult::Fail;
    }
    if prot.write {
        return TestResult::Fail;
    }
    if prot.execute {
        return TestResult::Fail;
    }
    if !prot.user {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_protection_flags_equality() -> TestResult {
    let prot1 = ProtectionFlags::new(true, true, false, true);
    let prot2 = ProtectionFlags::new(true, true, false, true);
    let prot3 = ProtectionFlags::new(true, false, false, true);
    if prot1 != prot2 {
        return TestResult::Fail;
    }
    if prot1 == prot3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_protection_flags_to_pte_flags() -> TestResult {
    let prot = ProtectionFlags::new(true, true, true, true);
    let flags = prot.to_pte_flags();
    if !(flags & pte_flags::PRESENT != 0) {
        return TestResult::Fail;
    }
    if !(flags & pte_flags::WRITABLE != 0) {
        return TestResult::Fail;
    }
    if !(flags & pte_flags::USER_ACCESSIBLE != 0) {
        return TestResult::Fail;
    }
    if !(flags & pte_flags::NO_EXECUTE == 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_protection_flags_no_exec_flag() -> TestResult {
    let prot = ProtectionFlags::new(true, false, false, true);
    let flags = prot.to_pte_flags();
    if !(flags & pte_flags::NO_EXECUTE != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
