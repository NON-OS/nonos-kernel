// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Signal constant and type tests

use crate::syscall::signals::*;
use crate::test::framework::TestResult;

pub(crate) fn test_sighup() -> TestResult {
    if SIGHUP != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigint() -> TestResult {
    if SIGINT != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigquit() -> TestResult {
    if SIGQUIT != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigill() -> TestResult {
    if SIGILL != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigtrap() -> TestResult {
    if SIGTRAP != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigabrt() -> TestResult {
    if SIGABRT != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigbus() -> TestResult {
    if SIGBUS != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigfpe() -> TestResult {
    if SIGFPE != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigkill() -> TestResult {
    if SIGKILL != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigusr1() -> TestResult {
    if SIGUSR1 != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigsegv() -> TestResult {
    if SIGSEGV != 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigusr2() -> TestResult {
    if SIGUSR2 != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigpipe() -> TestResult {
    if SIGPIPE != 13 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigalrm() -> TestResult {
    if SIGALRM != 14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigterm() -> TestResult {
    if SIGTERM != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigstkflt() -> TestResult {
    if SIGSTKFLT != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigchld() -> TestResult {
    if SIGCHLD != 17 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigcont() -> TestResult {
    if SIGCONT != 18 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigstop() -> TestResult {
    if SIGSTOP != 19 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigtstp() -> TestResult {
    if SIGTSTP != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigttin() -> TestResult {
    if SIGTTIN != 21 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigttou() -> TestResult {
    if SIGTTOU != 22 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigurg() -> TestResult {
    if SIGURG != 23 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigxcpu() -> TestResult {
    if SIGXCPU != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigxfsz() -> TestResult {
    if SIGXFSZ != 25 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigvtalrm() -> TestResult {
    if SIGVTALRM != 26 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigprof() -> TestResult {
    if SIGPROF != 27 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigwinch() -> TestResult {
    if SIGWINCH != 28 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigio() -> TestResult {
    if SIGIO != 29 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigpwr() -> TestResult {
    if SIGPWR != 30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigsys() -> TestResult {
    if SIGSYS != 31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigpoll_equals_sigio() -> TestResult {
    if SIGPOLL != SIGIO {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigrtmin() -> TestResult {
    if SIGRTMIN != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigrtmax() -> TestResult {
    if SIGRTMAX != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sig_dfl() -> TestResult {
    if SIG_DFL != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sig_ign() -> TestResult {
    if SIG_IGN != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sig_err() -> TestResult {
    if SIG_ERR != u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sa_nocldstop() -> TestResult {
    if SA_NOCLDSTOP != 0x00000001 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sa_nocldwait() -> TestResult {
    if SA_NOCLDWAIT != 0x00000002 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sa_siginfo() -> TestResult {
    if SA_SIGINFO != 0x00000004 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sa_onstack() -> TestResult {
    if SA_ONSTACK != 0x08000000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sa_restart() -> TestResult {
    if SA_RESTART != 0x10000000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sa_nodefer() -> TestResult {
    if SA_NODEFER != 0x40000000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sa_resethand() -> TestResult {
    if SA_RESETHAND != 0x80000000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sa_restorer() -> TestResult {
    if SA_RESTORER != 0x04000000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sig_block() -> TestResult {
    if SIG_BLOCK != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sig_unblock() -> TestResult {
    if SIG_UNBLOCK != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sig_setmask() -> TestResult {
    if SIG_SETMASK != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_new() -> TestResult {
    let set = SigSet::new();
    if set.0 != 0 {
        return TestResult::Fail;
    }
    if !set.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_full() -> TestResult {
    let set = SigSet::full();
    if set.0 != !0u64 {
        return TestResult::Fail;
    }
    if set.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_add() -> TestResult {
    let mut set = SigSet::new();
    set.add(SIGINT);
    if !set.contains(SIGINT) {
        return TestResult::Fail;
    }
    if set.contains(SIGTERM) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_add_multiple() -> TestResult {
    let mut set = SigSet::new();
    set.add(SIGINT);
    set.add(SIGTERM);
    set.add(SIGKILL);
    if !set.contains(SIGINT) {
        return TestResult::Fail;
    }
    if !set.contains(SIGTERM) {
        return TestResult::Fail;
    }
    if !set.contains(SIGKILL) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_remove() -> TestResult {
    let mut set = SigSet::new();
    set.add(SIGINT);
    set.add(SIGTERM);
    set.remove(SIGINT);
    if set.contains(SIGINT) {
        return TestResult::Fail;
    }
    if !set.contains(SIGTERM) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_contains_boundary_low() -> TestResult {
    let mut set = SigSet::new();
    set.add(1);
    if !set.contains(1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_contains_boundary_high() -> TestResult {
    let mut set = SigSet::new();
    set.add(64);
    if !set.contains(64) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_contains_invalid_zero() -> TestResult {
    let set = SigSet::full();
    if set.contains(0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_contains_invalid_over_64() -> TestResult {
    let set = SigSet::full();
    if set.contains(65) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_add_invalid_zero() -> TestResult {
    let mut set = SigSet::new();
    set.add(0);
    if !set.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_add_invalid_over_64() -> TestResult {
    let mut set = SigSet::new();
    set.add(100);
    if !set.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_not() -> TestResult {
    let set = SigSet::new();
    let inverted = !set;
    if inverted.0 != !0u64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_bitand() -> TestResult {
    let mut set1 = SigSet::new();
    set1.add(SIGINT);
    set1.add(SIGTERM);

    let mut set2 = SigSet::new();
    set2.add(SIGINT);
    set2.add(SIGKILL);

    let result = set1 & set2;
    if !result.contains(SIGINT) {
        return TestResult::Fail;
    }
    if result.contains(SIGTERM) {
        return TestResult::Fail;
    }
    if result.contains(SIGKILL) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_eq_u64() -> TestResult {
    let set = SigSet::new();
    if !(set == 0u64) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_default() -> TestResult {
    let set: SigSet = Default::default();
    if !set.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_clone() -> TestResult {
    let mut set = SigSet::new();
    set.add(SIGINT);
    let cloned = set.clone();
    if !cloned.contains(SIGINT) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigset_copy() -> TestResult {
    let mut set = SigSet::new();
    set.add(SIGINT);
    let copied = set;
    if !copied.contains(SIGINT) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kernel_sigaction_default() -> TestResult {
    let action: KernelSigAction = Default::default();
    if action.handler != SIG_DFL {
        return TestResult::Fail;
    }
    if action.flags != 0 {
        return TestResult::Fail;
    }
    if action.restorer != 0 {
        return TestResult::Fail;
    }
    if !action.mask.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kernel_sigaction_clone() -> TestResult {
    let mut action = KernelSigAction::default();
    action.handler = 0x1000;
    action.flags = SA_RESTART;
    let cloned = action.clone();
    if cloned.handler != 0x1000 {
        return TestResult::Fail;
    }
    if cloned.flags != SA_RESTART {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_process_signal_state_default() -> TestResult {
    let state: ProcessSignalState = Default::default();
    if !state.blocked.is_empty() {
        return TestResult::Fail;
    }
    if !state.pending.is_empty() {
        return TestResult::Fail;
    }
    if !state.pending_queue.is_empty() {
        return TestResult::Fail;
    }
    if !state.saved_mask.is_none() {
        return TestResult::Fail;
    }
    if !state.alt_stack.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_process_signal_state_actions_count() -> TestResult {
    let state = ProcessSignalState::default();
    if state.actions.len() != 65 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pending_signal_fields() -> TestResult {
    let sig = PendingSignal {
        signo: SIGINT,
        code: 0,
        pid: 1234,
        uid: 1000,
        value: 0,
        timestamp: 12345678,
    };
    if sig.signo != SIGINT {
        return TestResult::Fail;
    }
    if sig.pid != 1234 {
        return TestResult::Fail;
    }
    if sig.uid != 1000 {
        return TestResult::Fail;
    }
    if sig.timestamp != 12345678 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_realtime_signal_range() -> TestResult {
    if SIGRTMIN <= SIGSYS {
        return TestResult::Fail;
    }
    if SIGRTMAX < SIGRTMIN {
        return TestResult::Fail;
    }
    if SIGRTMAX - SIGRTMIN + 1 != 33 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_standard_signals_are_less_than_32() -> TestResult {
    if SIGHUP >= 32 {
        return TestResult::Fail;
    }
    if SIGINT >= 32 {
        return TestResult::Fail;
    }
    if SIGKILL >= 32 {
        return TestResult::Fail;
    }
    if SIGTERM >= 32 {
        return TestResult::Fail;
    }
    if SIGSYS >= 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sigkill_and_sigstop_special() -> TestResult {
    if SIGKILL != 9 {
        return TestResult::Fail;
    }
    if SIGSTOP != 19 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
