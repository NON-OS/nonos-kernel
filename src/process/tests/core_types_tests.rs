use crate::memory::addr::VirtAddr;
use crate::process::core::types::*;
use crate::test::framework::TestResult;
use x86_64::structures::paging::PageTableFlags;

pub fn process_state_variants() -> TestResult {
    let new = ProcessState::New;
    let ready = ProcessState::Ready;
    let running = ProcessState::Running;
    let sleeping = ProcessState::Sleeping;
    let stopped = ProcessState::Stopped;
    let zombie = ProcessState::Zombie(0);
    let terminated = ProcessState::Terminated(0);
    if new != ProcessState::New {
        return TestResult::Fail;
    }
    if ready != ProcessState::Ready {
        return TestResult::Fail;
    }
    if running != ProcessState::Running {
        return TestResult::Fail;
    }
    if sleeping != ProcessState::Sleeping {
        return TestResult::Fail;
    }
    if stopped != ProcessState::Stopped {
        return TestResult::Fail;
    }
    if zombie != ProcessState::Zombie(0) {
        return TestResult::Fail;
    }
    if terminated != ProcessState::Terminated(0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_state_zombie_with_code() -> TestResult {
    let zombie = ProcessState::Zombie(42);
    if zombie != ProcessState::Zombie(42) {
        return TestResult::Fail;
    }
    if zombie == ProcessState::Zombie(0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_state_terminated_with_code() -> TestResult {
    let term = ProcessState::Terminated(-1);
    if term != ProcessState::Terminated(-1) {
        return TestResult::Fail;
    }
    if term == ProcessState::Terminated(0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_state_clone() -> TestResult {
    let state = ProcessState::Running;
    let cloned = state;
    if state != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn priority_variants() -> TestResult {
    let idle = Priority::Idle;
    let low = Priority::Low;
    let normal = Priority::Normal;
    let high = Priority::High;
    let realtime = Priority::RealTime;
    if idle != Priority::Idle {
        return TestResult::Fail;
    }
    if low != Priority::Low {
        return TestResult::Fail;
    }
    if normal != Priority::Normal {
        return TestResult::Fail;
    }
    if high != Priority::High {
        return TestResult::Fail;
    }
    if realtime != Priority::RealTime {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn priority_not_equal() -> TestResult {
    if Priority::Idle == Priority::Low {
        return TestResult::Fail;
    }
    if Priority::Low == Priority::Normal {
        return TestResult::Fail;
    }
    if Priority::Normal == Priority::High {
        return TestResult::Fail;
    }
    if Priority::High == Priority::RealTime {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn priority_clone() -> TestResult {
    let prio = Priority::High;
    let cloned = prio;
    if prio != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn vma_basic() -> TestResult {
    let vma = Vma {
        start: VirtAddr::new(0x1000),
        end: VirtAddr::new(0x2000),
        flags: PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
    };
    if vma.start.as_u64() != 0x1000 {
        return TestResult::Fail;
    }
    if vma.end.as_u64() != 0x2000 {
        return TestResult::Fail;
    }
    if !vma.flags.contains(PageTableFlags::PRESENT) {
        return TestResult::Fail;
    }
    if !vma.flags.contains(PageTableFlags::WRITABLE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn vma_clone() -> TestResult {
    let vma1 = Vma {
        start: VirtAddr::new(0x3000),
        end: VirtAddr::new(0x4000),
        flags: PageTableFlags::PRESENT,
    };
    let vma2 = vma1.clone();
    if vma1.start != vma2.start {
        return TestResult::Fail;
    }
    if vma1.end != vma2.end {
        return TestResult::Fail;
    }
    if vma1.flags != vma2.flags {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn isolation_flags_default() -> TestResult {
    let flags = IsolationFlags::default();
    if !flags.no_network {
        return TestResult::Fail;
    }
    if !flags.no_filesystem {
        return TestResult::Fail;
    }
    if !flags.no_ipc {
        return TestResult::Fail;
    }
    if !flags.no_devices {
        return TestResult::Fail;
    }
    if !flags.memory_isolated {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn isolation_flags_clone() -> TestResult {
    let flags1 = IsolationFlags {
        no_network: false,
        no_filesystem: true,
        no_ipc: false,
        no_devices: true,
        no_signals: true,
        memory_isolated: true,
    };
    let flags2 = flags1;
    if flags1.no_network != flags2.no_network {
        return TestResult::Fail;
    }
    if flags1.no_filesystem != flags2.no_filesystem {
        return TestResult::Fail;
    }
    if flags1.no_ipc != flags2.no_ipc {
        return TestResult::Fail;
    }
    if flags1.no_devices != flags2.no_devices {
        return TestResult::Fail;
    }
    if flags1.memory_isolated != flags2.memory_isolated {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn suspended_context_fields() -> TestResult {
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
    if ctx.rax != 1 {
        return TestResult::Fail;
    }
    if ctx.rip != 0x401000 {
        return TestResult::Fail;
    }
    if ctx.rflags != 0x202 {
        return TestResult::Fail;
    }
    if ctx.suspended_at != 1234567890 {
        return TestResult::Fail;
    }
    if ctx.previous_state != ProcessState::Running {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn suspended_context_clone() -> TestResult {
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
    if ctx1.rax != ctx2.rax {
        return TestResult::Fail;
    }
    if ctx1.rip != ctx2.rip {
        return TestResult::Fail;
    }
    if ctx1.previous_state != ctx2.previous_state {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn align_up_power_of_two() -> TestResult {
    if align_up(0, 4096) != 0 {
        return TestResult::Fail;
    }
    if align_up(1, 4096) != 4096 {
        return TestResult::Fail;
    }
    if align_up(4095, 4096) != 4096 {
        return TestResult::Fail;
    }
    if align_up(4096, 4096) != 4096 {
        return TestResult::Fail;
    }
    if align_up(4097, 4096) != 8192 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn align_up_various_alignments() -> TestResult {
    if align_up(0, 8) != 0 {
        return TestResult::Fail;
    }
    if align_up(1, 8) != 8 {
        return TestResult::Fail;
    }
    if align_up(7, 8) != 8 {
        return TestResult::Fail;
    }
    if align_up(8, 8) != 8 {
        return TestResult::Fail;
    }
    if align_up(9, 8) != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn align_up_alignment_1() -> TestResult {
    if align_up(0, 1) != 0 {
        return TestResult::Fail;
    }
    if align_up(1, 1) != 1 {
        return TestResult::Fail;
    }
    if align_up(100, 1) != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn overlaps_no_overlap() -> TestResult {
    let vmas = [
        Vma {
            start: VirtAddr::new(0x1000),
            end: VirtAddr::new(0x2000),
            flags: PageTableFlags::empty(),
        },
        Vma {
            start: VirtAddr::new(0x3000),
            end: VirtAddr::new(0x4000),
            flags: PageTableFlags::empty(),
        },
    ];
    if overlaps(&vmas, VirtAddr::new(0x2000), 0x1000) {
        return TestResult::Fail;
    }
    if overlaps(&vmas, VirtAddr::new(0x5000), 0x1000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn overlaps_with_first() -> TestResult {
    let vmas = [Vma {
        start: VirtAddr::new(0x1000),
        end: VirtAddr::new(0x2000),
        flags: PageTableFlags::empty(),
    }];
    if !overlaps(&vmas, VirtAddr::new(0x1500), 0x100) {
        return TestResult::Fail;
    }
    if !overlaps(&vmas, VirtAddr::new(0x0500), 0x1000) {
        return TestResult::Fail;
    }
    if !overlaps(&vmas, VirtAddr::new(0x1FFF), 0x100) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn overlaps_adjacent() -> TestResult {
    let vmas = [Vma {
        start: VirtAddr::new(0x1000),
        end: VirtAddr::new(0x2000),
        flags: PageTableFlags::empty(),
    }];
    if overlaps(&vmas, VirtAddr::new(0x2000), 0x1000) {
        return TestResult::Fail;
    }
    if overlaps(&vmas, VirtAddr::new(0x0000), 0x1000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn overlaps_empty_vmas() -> TestResult {
    let vmas: [Vma; 0] = [];
    if overlaps(&vmas, VirtAddr::new(0x1000), 0x1000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn overlaps_zero_length() -> TestResult {
    let vmas = [Vma {
        start: VirtAddr::new(0x1000),
        end: VirtAddr::new(0x2000),
        flags: PageTableFlags::empty(),
    }];
    if overlaps(&vmas, VirtAddr::new(0x1500), 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn pid_type_alias() -> TestResult {
    let pid: Pid = 12345;
    if pid != 12345u32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn tid_type_alias() -> TestResult {
    let tid: Tid = 67890;
    if tid != 67890u32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
