use crate::process::core::types::*;
use x86_64::VirtAddr;
use x86_64::structures::paging::PageTableFlags;

#[test]
fn process_state_variants() {
    let new = ProcessState::New;
    let ready = ProcessState::Ready;
    let running = ProcessState::Running;
    let sleeping = ProcessState::Sleeping;
    let stopped = ProcessState::Stopped;
    let zombie = ProcessState::Zombie(0);
    let terminated = ProcessState::Terminated(0);
    assert_eq!(new, ProcessState::New);
    assert_eq!(ready, ProcessState::Ready);
    assert_eq!(running, ProcessState::Running);
    assert_eq!(sleeping, ProcessState::Sleeping);
    assert_eq!(stopped, ProcessState::Stopped);
    assert_eq!(zombie, ProcessState::Zombie(0));
    assert_eq!(terminated, ProcessState::Terminated(0));
}

#[test]
fn process_state_zombie_with_code() {
    let zombie = ProcessState::Zombie(42);
    assert_eq!(zombie, ProcessState::Zombie(42));
    assert_ne!(zombie, ProcessState::Zombie(0));
}

#[test]
fn process_state_terminated_with_code() {
    let term = ProcessState::Terminated(-1);
    assert_eq!(term, ProcessState::Terminated(-1));
    assert_ne!(term, ProcessState::Terminated(0));
}

#[test]
fn process_state_clone() {
    let state = ProcessState::Running;
    let cloned = state;
    assert_eq!(state, cloned);
}

#[test]
fn priority_variants() {
    let idle = Priority::Idle;
    let low = Priority::Low;
    let normal = Priority::Normal;
    let high = Priority::High;
    let realtime = Priority::RealTime;
    assert_eq!(idle, Priority::Idle);
    assert_eq!(low, Priority::Low);
    assert_eq!(normal, Priority::Normal);
    assert_eq!(high, Priority::High);
    assert_eq!(realtime, Priority::RealTime);
}

#[test]
fn priority_not_equal() {
    assert_ne!(Priority::Idle, Priority::Low);
    assert_ne!(Priority::Low, Priority::Normal);
    assert_ne!(Priority::Normal, Priority::High);
    assert_ne!(Priority::High, Priority::RealTime);
}

#[test]
fn priority_clone() {
    let prio = Priority::High;
    let cloned = prio;
    assert_eq!(prio, cloned);
}

#[test]
fn vma_basic() {
    let vma = Vma {
        start: VirtAddr::new(0x1000),
        end: VirtAddr::new(0x2000),
        flags: PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
    };
    assert_eq!(vma.start.as_u64(), 0x1000);
    assert_eq!(vma.end.as_u64(), 0x2000);
    assert!(vma.flags.contains(PageTableFlags::PRESENT));
    assert!(vma.flags.contains(PageTableFlags::WRITABLE));
}

#[test]
fn vma_clone() {
    let vma1 = Vma {
        start: VirtAddr::new(0x3000),
        end: VirtAddr::new(0x4000),
        flags: PageTableFlags::PRESENT,
    };
    let vma2 = vma1.clone();
    assert_eq!(vma1.start, vma2.start);
    assert_eq!(vma1.end, vma2.end);
    assert_eq!(vma1.flags, vma2.flags);
}

#[test]
fn isolation_flags_default() {
    let flags = IsolationFlags::default();
    assert!(flags.no_network);
    assert!(flags.no_filesystem);
    assert!(flags.no_ipc);
    assert!(flags.no_devices);
    assert!(flags.memory_isolated);
}

#[test]
fn isolation_flags_clone() {
    let flags1 = IsolationFlags {
        no_network: false,
        no_filesystem: true,
        no_ipc: false,
        no_devices: true,
        memory_isolated: true,
    };
    let flags2 = flags1;
    assert_eq!(flags1.no_network, flags2.no_network);
    assert_eq!(flags1.no_filesystem, flags2.no_filesystem);
    assert_eq!(flags1.no_ipc, flags2.no_ipc);
    assert_eq!(flags1.no_devices, flags2.no_devices);
    assert_eq!(flags1.memory_isolated, flags2.memory_isolated);
}

#[test]
fn suspended_context_fields() {
    let ctx = SuspendedContext {
        rax: 1,
        rbx: 2,
        rcx: 3,
        rdx: 4,
        rsi: 5,
        rdi: 6,
        rbp: 7,
        rsp: 8,
        r8: 9,
        r9: 10,
        r10: 11,
        r11: 12,
        r12: 13,
        r13: 14,
        r14: 15,
        r15: 16,
        rip: 0x401000,
        rflags: 0x202,
        suspended_at: 1234567890,
        previous_state: ProcessState::Running,
    };
    assert_eq!(ctx.rax, 1);
    assert_eq!(ctx.rip, 0x401000);
    assert_eq!(ctx.rflags, 0x202);
    assert_eq!(ctx.suspended_at, 1234567890);
    assert_eq!(ctx.previous_state, ProcessState::Running);
}

#[test]
fn suspended_context_clone() {
    let ctx1 = SuspendedContext {
        rax: 100,
        rbx: 200,
        rcx: 300,
        rdx: 400,
        rsi: 500,
        rdi: 600,
        rbp: 700,
        rsp: 800,
        r8: 900,
        r9: 1000,
        r10: 1100,
        r11: 1200,
        r12: 1300,
        r13: 1400,
        r14: 1500,
        r15: 1600,
        rip: 0xdead_beef,
        rflags: 0x246,
        suspended_at: 999,
        previous_state: ProcessState::Sleeping,
    };
    let ctx2 = ctx1.clone();
    assert_eq!(ctx1.rax, ctx2.rax);
    assert_eq!(ctx1.rip, ctx2.rip);
    assert_eq!(ctx1.previous_state, ctx2.previous_state);
}

#[test]
fn align_up_power_of_two() {
    assert_eq!(align_up(0, 4096), 0);
    assert_eq!(align_up(1, 4096), 4096);
    assert_eq!(align_up(4095, 4096), 4096);
    assert_eq!(align_up(4096, 4096), 4096);
    assert_eq!(align_up(4097, 4096), 8192);
}

#[test]
fn align_up_various_alignments() {
    assert_eq!(align_up(0, 8), 0);
    assert_eq!(align_up(1, 8), 8);
    assert_eq!(align_up(7, 8), 8);
    assert_eq!(align_up(8, 8), 8);
    assert_eq!(align_up(9, 8), 16);
}

#[test]
fn align_up_alignment_1() {
    assert_eq!(align_up(0, 1), 0);
    assert_eq!(align_up(1, 1), 1);
    assert_eq!(align_up(100, 1), 100);
}

#[test]
fn overlaps_no_overlap() {
    let vmas = [
        Vma { start: VirtAddr::new(0x1000), end: VirtAddr::new(0x2000), flags: PageTableFlags::empty() },
        Vma { start: VirtAddr::new(0x3000), end: VirtAddr::new(0x4000), flags: PageTableFlags::empty() },
    ];
    assert!(!overlaps(&vmas, VirtAddr::new(0x2000), 0x1000));
    assert!(!overlaps(&vmas, VirtAddr::new(0x5000), 0x1000));
}

#[test]
fn overlaps_with_first() {
    let vmas = [
        Vma { start: VirtAddr::new(0x1000), end: VirtAddr::new(0x2000), flags: PageTableFlags::empty() },
    ];
    assert!(overlaps(&vmas, VirtAddr::new(0x1500), 0x100));
    assert!(overlaps(&vmas, VirtAddr::new(0x0500), 0x1000));
    assert!(overlaps(&vmas, VirtAddr::new(0x1FFF), 0x100));
}

#[test]
fn overlaps_adjacent() {
    let vmas = [
        Vma { start: VirtAddr::new(0x1000), end: VirtAddr::new(0x2000), flags: PageTableFlags::empty() },
    ];
    assert!(!overlaps(&vmas, VirtAddr::new(0x2000), 0x1000));
    assert!(!overlaps(&vmas, VirtAddr::new(0x0000), 0x1000));
}

#[test]
fn overlaps_empty_vmas() {
    let vmas: [Vma; 0] = [];
    assert!(!overlaps(&vmas, VirtAddr::new(0x1000), 0x1000));
}

#[test]
fn overlaps_zero_length() {
    let vmas = [
        Vma { start: VirtAddr::new(0x1000), end: VirtAddr::new(0x2000), flags: PageTableFlags::empty() },
    ];
    assert!(!overlaps(&vmas, VirtAddr::new(0x1500), 0));
}

#[test]
fn pid_type_alias() {
    let pid: Pid = 12345;
    assert_eq!(pid, 12345u32);
}

#[test]
fn tid_type_alias() {
    let tid: Tid = 67890;
    assert_eq!(tid, 67890u32);
}
