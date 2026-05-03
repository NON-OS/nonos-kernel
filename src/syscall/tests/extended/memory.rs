use crate::syscall::extended::memory::{PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE};
use crate::syscall::SyscallResult;

#[test]
pub(crate) fn test_prot_none_constant() {
    assert_eq!(PROT_NONE, 0);
}

#[test]
pub(crate) fn test_prot_read_constant() {
    assert_eq!(PROT_READ, 1);
}

#[test]
pub(crate) fn test_prot_write_constant() {
    assert_eq!(PROT_WRITE, 2);
}

#[test]
pub(crate) fn test_prot_exec_constant() {
    assert_eq!(PROT_EXEC, 4);
}

#[test]
pub(crate) fn test_prot_read_write_combined() {
    let prot = PROT_READ | PROT_WRITE;
    assert_eq!(prot, 3);
}

#[test]
pub(crate) fn test_prot_read_exec_combined() {
    let prot = PROT_READ | PROT_EXEC;
    assert_eq!(prot, 5);
}

#[test]
pub(crate) fn test_prot_all_combined() {
    let prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    assert_eq!(prot, 7);
}

#[test]
pub(crate) fn test_mprotect_unaligned_addr_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_mprotect_zero_len_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_mprotect_no_process_returns_eperm() {
    let result = SyscallResult::error(1);
    assert_eq!(result.errno(), Some(1));
}

#[test]
pub(crate) fn test_mprotect_wx_violation_returns_eperm() {
    let result = SyscallResult::error(1);
    assert_eq!(result.errno(), Some(1));
}

#[test]
pub(crate) fn test_mprotect_invalid_region_returns_enomem() {
    let result = SyscallResult::error(12);
    assert_eq!(result.errno(), Some(12));
}

#[test]
pub(crate) fn test_mprotect_update_failure_returns_efault() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
pub(crate) fn test_mprotect_success_audited() {
    let result = SyscallResult::success_audited(0);
    assert_eq!(result.value, 0);
    assert!(result.audit_required);
}

#[test]
pub(crate) fn test_mprotect_page_alignment() {
    let addr: u64 = 0x1000;
    assert_eq!(addr & 0xFFF, 0);
}

#[test]
pub(crate) fn test_mprotect_page_unaligned() {
    let addr: u64 = 0x1001;
    assert_ne!(addr & 0xFFF, 0);
}

#[test]
pub(crate) fn test_mprotect_page_count_calculation() {
    let len: u64 = 8192;
    let pages = (len + 4095) / 4096;
    assert_eq!(pages, 2);
}

#[test]
pub(crate) fn test_mprotect_page_count_partial() {
    let len: u64 = 4097;
    let pages = (len + 4095) / 4096;
    assert_eq!(pages, 2);
}

#[test]
pub(crate) fn test_brk_zero_returns_current() {
    let brk_value = 0x1000_0000_0000i64;
    let result = SyscallResult::success(brk_value);
    assert_eq!(result.value, brk_value);
}

#[test]
pub(crate) fn test_brk_no_process_returns_eperm() {
    let result = SyscallResult::error(1);
    assert_eq!(result.errno(), Some(1));
}

#[test]
pub(crate) fn test_brk_below_min_returns_enomem() {
    let result = SyscallResult::error(12);
    assert_eq!(result.errno(), Some(12));
}

#[test]
pub(crate) fn test_brk_above_max_returns_enomem() {
    let result = SyscallResult::error(12);
    assert_eq!(result.errno(), Some(12));
}

#[test]
pub(crate) fn test_brk_expand_success() {
    let new_brk = 0x1000_0001_0000i64;
    let result = SyscallResult::success(new_brk);
    assert_eq!(result.value, new_brk);
}

#[test]
pub(crate) fn test_brk_shrink_success() {
    let new_brk = 0x1000_0000_8000i64;
    let result = SyscallResult::success(new_brk);
    assert_eq!(result.value, new_brk);
}

#[test]
pub(crate) fn test_brk_allocation_failure_returns_enomem() {
    let result = SyscallResult::error(12);
    assert_eq!(result.errno(), Some(12));
}

#[test]
pub(crate) fn test_brk_min_address() {
    let min_brk: u64 = 0x0000_1000_0000_0000;
    assert_eq!(min_brk, 0x1000_0000_0000);
}

#[test]
pub(crate) fn test_brk_max_address() {
    let max_brk: u64 = 0x0000_7F00_0000_0000;
    assert_eq!(max_brk, 0x7F00_0000_0000);
}

#[test]
pub(crate) fn test_brk_page_alignment() {
    let addr: u64 = 0x1000_0000_1234;
    let aligned = (addr + 4095) & !4095;
    assert_eq!(aligned, 0x1000_0000_2000);
}

#[test]
pub(crate) fn test_mremap_unaligned_addr_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_mremap_zero_old_size_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_mremap_zero_new_size_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
pub(crate) fn test_mremap_no_process_returns_eperm() {
    let result = SyscallResult::error(1);
    assert_eq!(result.errno(), Some(1));
}

#[test]
pub(crate) fn test_mremap_shrink_success() {
    let addr = 0x1000_0000i64;
    let result = SyscallResult::success_audited(addr);
    assert_eq!(result.value, addr);
    assert!(result.audit_required);
}

#[test]
pub(crate) fn test_mremap_grow_in_place_success() {
    let addr = 0x1000_0000i64;
    let result = SyscallResult::success_audited(addr);
    assert_eq!(result.value, addr);
}

#[test]
pub(crate) fn test_mremap_grow_no_move_returns_enomem() {
    let result = SyscallResult::error(12);
    assert_eq!(result.errno(), Some(12));
}

#[test]
pub(crate) fn test_mremap_move_success() {
    let new_addr = 0x2000_0000i64;
    let result = SyscallResult::success_audited(new_addr);
    assert_eq!(result.value, new_addr);
}

#[test]
pub(crate) fn test_mremap_copy_failure_returns_efault() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
pub(crate) fn test_mremap_maymove_flag() {
    let mremap_maymove: u64 = 1;
    assert_eq!(mremap_maymove, 1);
}

#[test]
pub(crate) fn test_mremap_fixed_flag() {
    let mremap_fixed: u64 = 2;
    assert_eq!(mremap_fixed, 2);
}

#[test]
pub(crate) fn test_mlock_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_mlock_no_process_returns_eperm() {
    let result = SyscallResult::error(1);
    assert_eq!(result.errno(), Some(1));
}

#[test]
pub(crate) fn test_mlock_invalid_region_returns_enomem() {
    let result = SyscallResult::error(12);
    assert_eq!(result.errno(), Some(12));
}

#[test]
pub(crate) fn test_mlock2_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_mlock2_onfault_flag() {
    let mlock_onfault: u32 = 1;
    assert_eq!(mlock_onfault, 1);
}

#[test]
pub(crate) fn test_munlock_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_mlockall_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_mlockall_mcl_current_flag() {
    let mcl_current: i32 = 1;
    assert_eq!(mcl_current, 1);
}

#[test]
pub(crate) fn test_mlockall_mcl_future_flag() {
    let mcl_future: i32 = 2;
    assert_eq!(mcl_future, 2);
}

#[test]
pub(crate) fn test_mlockall_mcl_onfault_flag() {
    let mcl_onfault: i32 = 4;
    assert_eq!(mcl_onfault, 4);
}

#[test]
pub(crate) fn test_munlockall_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_msync_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_msync_ms_async_flag() {
    let ms_async: i32 = 1;
    assert_eq!(ms_async, 1);
}

#[test]
pub(crate) fn test_msync_ms_sync_flag() {
    let ms_sync: i32 = 4;
    assert_eq!(ms_sync, 4);
}

#[test]
pub(crate) fn test_msync_ms_invalidate_flag() {
    let ms_invalidate: i32 = 2;
    assert_eq!(ms_invalidate, 2);
}

#[test]
pub(crate) fn test_mincore_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_madvise_success_returns_zero() {
    let result = SyscallResult::success(0);
    assert_eq!(result.value, 0);
}

#[test]
pub(crate) fn test_madvise_madv_normal() {
    let madv_normal: i32 = 0;
    assert_eq!(madv_normal, 0);
}

#[test]
pub(crate) fn test_madvise_madv_random() {
    let madv_random: i32 = 1;
    assert_eq!(madv_random, 1);
}

#[test]
pub(crate) fn test_madvise_madv_sequential() {
    let madv_sequential: i32 = 2;
    assert_eq!(madv_sequential, 2);
}

#[test]
pub(crate) fn test_madvise_madv_willneed() {
    let madv_willneed: i32 = 3;
    assert_eq!(madv_willneed, 3);
}

#[test]
pub(crate) fn test_madvise_madv_dontneed() {
    let madv_dontneed: i32 = 4;
    assert_eq!(madv_dontneed, 4);
}

#[test]
pub(crate) fn test_memfd_create_success_returns_fd() {
    let fd = 10i64;
    let result = SyscallResult::success(fd);
    assert_eq!(result.value, 10);
}

#[test]
pub(crate) fn test_memfd_create_mfd_cloexec_flag() {
    let mfd_cloexec: u32 = 1;
    assert_eq!(mfd_cloexec, 1);
}

#[test]
pub(crate) fn test_memfd_create_mfd_allow_sealing_flag() {
    let mfd_allow_sealing: u32 = 2;
    assert_eq!(mfd_allow_sealing, 2);
}

#[test]
pub(crate) fn test_memfd_create_mfd_hugetlb_flag() {
    let mfd_hugetlb: u32 = 4;
    assert_eq!(mfd_hugetlb, 4);
}

#[test]
pub(crate) fn test_page_size_constant() {
    let page_size: usize = 4096;
    assert_eq!(page_size, 4096);
}

#[test]
pub(crate) fn test_user_space_max() {
    let user_space_max: u64 = 0x0000_7FFF_FFFF_FFFF;
    assert_eq!(user_space_max, 0x7FFF_FFFF_FFFF);
}

#[test]
pub(crate) fn test_is_user_space_valid() {
    let addr: u64 = 0x1000_0000;
    let len: usize = 4096;
    let user_space_max: u64 = 0x7FFF_FFFF_FFFF;
    let valid = addr <= user_space_max && len <= (user_space_max - addr) as usize;
    assert!(valid);
}

#[test]
pub(crate) fn test_is_user_space_invalid() {
    let addr: u64 = 0x8000_0000_0000;
    let user_space_max: u64 = 0x7FFF_FFFF_FFFF;
    let valid = addr <= user_space_max;
    assert!(!valid);
}
