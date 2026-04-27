use crate::process::clone_flags::*;
use crate::test::framework::TestResult;

pub fn clone_flags_bit_positions() -> TestResult {
    if CLONE_VM != 0x00000100 {
        return TestResult::Fail;
    }
    if CLONE_FS != 0x00000200 {
        return TestResult::Fail;
    }
    if CLONE_FILES != 0x00000400 {
        return TestResult::Fail;
    }
    if CLONE_SIGHAND != 0x00000800 {
        return TestResult::Fail;
    }
    if CLONE_THREAD != 0x00010000 {
        return TestResult::Fail;
    }
    if CLONE_NEWPID != 0x20000000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn clone_flags_namespace_bits() -> TestResult {
    if CLONE_NEWUSER != 0x10000000 {
        return TestResult::Fail;
    }
    if CLONE_NEWNET != 0x40000000 {
        return TestResult::Fail;
    }
    if CLONE_NEWIPC != 0x08000000 {
        return TestResult::Fail;
    }
    if CLONE_NEWNS != 0x00020000 {
        return TestResult::Fail;
    }
    if CLONE_NEWUTS != 0x04000000 {
        return TestResult::Fail;
    }
    if CLONE_NEWCGROUP != 0x02000000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn clone_flags_tid_bits() -> TestResult {
    if CLONE_PARENT_SETTID != 0x00100000 {
        return TestResult::Fail;
    }
    if CLONE_CHILD_CLEARTID != 0x00200000 {
        return TestResult::Fail;
    }
    if CLONE_CHILD_SETTID != 0x01000000 {
        return TestResult::Fail;
    }
    if CLONE_SETTLS != 0x00080000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn clone_flags_special() -> TestResult {
    if CLONE_DETACHED != 0x00400000 {
        return TestResult::Fail;
    }
    if CLONE_PARENT != 0x00008000 {
        return TestResult::Fail;
    }
    if CLONE_VFORK != 0x00004000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn clone_args_default() -> TestResult {
    let args = CloneArgs::default();
    if args.flags != 0 {
        return TestResult::Fail;
    }
    if args.pidfd != 0 {
        return TestResult::Fail;
    }
    if args.child_tid != 0 {
        return TestResult::Fail;
    }
    if args.parent_tid != 0 {
        return TestResult::Fail;
    }
    if args.exit_signal != 0 {
        return TestResult::Fail;
    }
    if args.stack != 0 {
        return TestResult::Fail;
    }
    if args.stack_size != 0 {
        return TestResult::Fail;
    }
    if args.tls != 0 {
        return TestResult::Fail;
    }
    if args.set_tid != 0 {
        return TestResult::Fail;
    }
    if args.set_tid_size != 0 {
        return TestResult::Fail;
    }
    if args.cgroup != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn clone_args_with_flags() -> TestResult {
    let args = CloneArgs { flags: CLONE_VM | CLONE_FS | CLONE_FILES, ..Default::default() };
    if args.flags & CLONE_VM == 0 {
        return TestResult::Fail;
    }
    if args.flags & CLONE_FS == 0 {
        return TestResult::Fail;
    }
    if args.flags & CLONE_FILES == 0 {
        return TestResult::Fail;
    }
    if args.flags & CLONE_THREAD != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn clone_args_thread_creation() -> TestResult {
    let args = CloneArgs {
        flags: CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD,
        stack: 0x7fff_0000_0000,
        stack_size: 8 * 1024 * 1024,
        ..Default::default()
    };
    if args.flags & CLONE_THREAD == 0 {
        return TestResult::Fail;
    }
    if args.stack != 0x7fff_0000_0000 {
        return TestResult::Fail;
    }
    if args.stack_size != 8 * 1024 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn clone_args_with_tls() -> TestResult {
    let args = CloneArgs { flags: CLONE_SETTLS, tls: 0x1234_5678, ..Default::default() };
    if args.flags & CLONE_SETTLS == 0 {
        return TestResult::Fail;
    }
    if args.tls != 0x1234_5678 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn clone_args_with_child_tid() -> TestResult {
    let args = CloneArgs {
        flags: CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
        child_tid: 0xdead_beef,
        ..Default::default()
    };
    if args.flags & CLONE_CHILD_SETTID == 0 {
        return TestResult::Fail;
    }
    if args.flags & CLONE_CHILD_CLEARTID == 0 {
        return TestResult::Fail;
    }
    if args.child_tid != 0xdead_beef {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn clone_args_with_parent_tid() -> TestResult {
    let args =
        CloneArgs { flags: CLONE_PARENT_SETTID, parent_tid: 0xcafe_babe, ..Default::default() };
    if args.flags & CLONE_PARENT_SETTID == 0 {
        return TestResult::Fail;
    }
    if args.parent_tid != 0xcafe_babe {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn clone_args_clone() -> TestResult {
    let args1 = CloneArgs {
        flags: CLONE_VM | CLONE_FS,
        stack: 0x1000,
        stack_size: 4096,
        ..Default::default()
    };
    let args2 = args1.clone();
    if args1.flags != args2.flags {
        return TestResult::Fail;
    }
    if args1.stack != args2.stack {
        return TestResult::Fail;
    }
    if args1.stack_size != args2.stack_size {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn clone_flags_no_overlap() -> TestResult {
    let namespace_flags = [
        CLONE_NEWPID,
        CLONE_NEWUSER,
        CLONE_NEWNET,
        CLONE_NEWIPC,
        CLONE_NEWNS,
        CLONE_NEWUTS,
        CLONE_NEWCGROUP,
    ];
    for i in 0..namespace_flags.len() {
        for j in (i + 1)..namespace_flags.len() {
            if namespace_flags[i] & namespace_flags[j] != 0 {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub fn clone_sighand_mask_value() -> TestResult {
    if CLONE_SIGHAND_MASK != 0x000000FF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn clone_args_full_namespace_isolation() -> TestResult {
    let args = CloneArgs {
        flags: CLONE_NEWPID
            | CLONE_NEWUSER
            | CLONE_NEWNET
            | CLONE_NEWIPC
            | CLONE_NEWNS
            | CLONE_NEWUTS
            | CLONE_NEWCGROUP,
        ..Default::default()
    };
    if args.flags & CLONE_NEWPID == 0 {
        return TestResult::Fail;
    }
    if args.flags & CLONE_NEWUSER == 0 {
        return TestResult::Fail;
    }
    if args.flags & CLONE_NEWNET == 0 {
        return TestResult::Fail;
    }
    if args.flags & CLONE_NEWIPC == 0 {
        return TestResult::Fail;
    }
    if args.flags & CLONE_NEWNS == 0 {
        return TestResult::Fail;
    }
    if args.flags & CLONE_NEWUTS == 0 {
        return TestResult::Fail;
    }
    if args.flags & CLONE_NEWCGROUP == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
