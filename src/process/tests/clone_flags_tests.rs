use crate::process::clone_flags::*;

#[test]
fn clone_flags_bit_positions() {
    assert_eq!(CLONE_VM, 0x00000100);
    assert_eq!(CLONE_FS, 0x00000200);
    assert_eq!(CLONE_FILES, 0x00000400);
    assert_eq!(CLONE_SIGHAND, 0x00000800);
    assert_eq!(CLONE_THREAD, 0x00010000);
    assert_eq!(CLONE_NEWPID, 0x20000000);
}

#[test]
fn clone_flags_namespace_bits() {
    assert_eq!(CLONE_NEWUSER, 0x10000000);
    assert_eq!(CLONE_NEWNET, 0x40000000);
    assert_eq!(CLONE_NEWIPC, 0x08000000);
    assert_eq!(CLONE_NEWNS, 0x00020000);
    assert_eq!(CLONE_NEWUTS, 0x04000000);
    assert_eq!(CLONE_NEWCGROUP, 0x02000000);
}

#[test]
fn clone_flags_tid_bits() {
    assert_eq!(CLONE_PARENT_SETTID, 0x00100000);
    assert_eq!(CLONE_CHILD_CLEARTID, 0x00200000);
    assert_eq!(CLONE_CHILD_SETTID, 0x01000000);
    assert_eq!(CLONE_SETTLS, 0x00080000);
}

#[test]
fn clone_flags_special() {
    assert_eq!(CLONE_DETACHED, 0x00400000);
    assert_eq!(CLONE_PARENT, 0x00008000);
    assert_eq!(CLONE_VFORK, 0x00004000);
}

#[test]
fn clone_args_default() {
    let args = CloneArgs::default();
    assert_eq!(args.flags, 0);
    assert_eq!(args.pidfd, 0);
    assert_eq!(args.child_tid, 0);
    assert_eq!(args.parent_tid, 0);
    assert_eq!(args.exit_signal, 0);
    assert_eq!(args.stack, 0);
    assert_eq!(args.stack_size, 0);
    assert_eq!(args.tls, 0);
    assert_eq!(args.set_tid, 0);
    assert_eq!(args.set_tid_size, 0);
    assert_eq!(args.cgroup, 0);
}

#[test]
fn clone_args_with_flags() {
    let args = CloneArgs {
        flags: CLONE_VM | CLONE_FS | CLONE_FILES,
        ..Default::default()
    };
    assert_ne!(args.flags & CLONE_VM, 0);
    assert_ne!(args.flags & CLONE_FS, 0);
    assert_ne!(args.flags & CLONE_FILES, 0);
    assert_eq!(args.flags & CLONE_THREAD, 0);
}

#[test]
fn clone_args_thread_creation() {
    let args = CloneArgs {
        flags: CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD,
        stack: 0x7fff_0000_0000,
        stack_size: 8 * 1024 * 1024,
        ..Default::default()
    };
    assert_ne!(args.flags & CLONE_THREAD, 0);
    assert_eq!(args.stack, 0x7fff_0000_0000);
    assert_eq!(args.stack_size, 8 * 1024 * 1024);
}

#[test]
fn clone_args_with_tls() {
    let args = CloneArgs {
        flags: CLONE_SETTLS,
        tls: 0x1234_5678,
        ..Default::default()
    };
    assert_ne!(args.flags & CLONE_SETTLS, 0);
    assert_eq!(args.tls, 0x1234_5678);
}

#[test]
fn clone_args_with_child_tid() {
    let args = CloneArgs {
        flags: CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
        child_tid: 0xdead_beef,
        ..Default::default()
    };
    assert_ne!(args.flags & CLONE_CHILD_SETTID, 0);
    assert_ne!(args.flags & CLONE_CHILD_CLEARTID, 0);
    assert_eq!(args.child_tid, 0xdead_beef);
}

#[test]
fn clone_args_with_parent_tid() {
    let args = CloneArgs {
        flags: CLONE_PARENT_SETTID,
        parent_tid: 0xcafe_babe,
        ..Default::default()
    };
    assert_ne!(args.flags & CLONE_PARENT_SETTID, 0);
    assert_eq!(args.parent_tid, 0xcafe_babe);
}

#[test]
fn clone_args_clone() {
    let args1 = CloneArgs {
        flags: CLONE_VM | CLONE_FS,
        stack: 0x1000,
        stack_size: 4096,
        ..Default::default()
    };
    let args2 = args1.clone();
    assert_eq!(args1.flags, args2.flags);
    assert_eq!(args1.stack, args2.stack);
    assert_eq!(args1.stack_size, args2.stack_size);
}

#[test]
fn clone_flags_no_overlap() {
    let namespace_flags = [
        CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWNET, CLONE_NEWIPC, CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWCGROUP
    ];
    for i in 0..namespace_flags.len() {
        for j in (i + 1)..namespace_flags.len() {
            assert_eq!(namespace_flags[i] & namespace_flags[j], 0);
        }
    }
}

#[test]
fn clone_sighand_mask_value() {
    assert_eq!(CLONE_SIGHAND_MASK, 0x000000FF);
}

#[test]
fn clone_args_full_namespace_isolation() {
    let args = CloneArgs {
        flags: CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWCGROUP,
        ..Default::default()
    };
    assert_ne!(args.flags & CLONE_NEWPID, 0);
    assert_ne!(args.flags & CLONE_NEWUSER, 0);
    assert_ne!(args.flags & CLONE_NEWNET, 0);
    assert_ne!(args.flags & CLONE_NEWIPC, 0);
    assert_ne!(args.flags & CLONE_NEWNS, 0);
    assert_ne!(args.flags & CLONE_NEWUTS, 0);
    assert_ne!(args.flags & CLONE_NEWCGROUP, 0);
}
