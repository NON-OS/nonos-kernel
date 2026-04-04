// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use crate::syscall::signals::*;

#[test]
fn test_sighup() {
    assert_eq!(SIGHUP, 1);
}

#[test]
fn test_sigint() {
    assert_eq!(SIGINT, 2);
}

#[test]
fn test_sigquit() {
    assert_eq!(SIGQUIT, 3);
}

#[test]
fn test_sigill() {
    assert_eq!(SIGILL, 4);
}

#[test]
fn test_sigtrap() {
    assert_eq!(SIGTRAP, 5);
}

#[test]
fn test_sigabrt() {
    assert_eq!(SIGABRT, 6);
}

#[test]
fn test_sigbus() {
    assert_eq!(SIGBUS, 7);
}

#[test]
fn test_sigfpe() {
    assert_eq!(SIGFPE, 8);
}

#[test]
fn test_sigkill() {
    assert_eq!(SIGKILL, 9);
}

#[test]
fn test_sigusr1() {
    assert_eq!(SIGUSR1, 10);
}

#[test]
fn test_sigsegv() {
    assert_eq!(SIGSEGV, 11);
}

#[test]
fn test_sigusr2() {
    assert_eq!(SIGUSR2, 12);
}

#[test]
fn test_sigpipe() {
    assert_eq!(SIGPIPE, 13);
}

#[test]
fn test_sigalrm() {
    assert_eq!(SIGALRM, 14);
}

#[test]
fn test_sigterm() {
    assert_eq!(SIGTERM, 15);
}

#[test]
fn test_sigstkflt() {
    assert_eq!(SIGSTKFLT, 16);
}

#[test]
fn test_sigchld() {
    assert_eq!(SIGCHLD, 17);
}

#[test]
fn test_sigcont() {
    assert_eq!(SIGCONT, 18);
}

#[test]
fn test_sigstop() {
    assert_eq!(SIGSTOP, 19);
}

#[test]
fn test_sigtstp() {
    assert_eq!(SIGTSTP, 20);
}

#[test]
fn test_sigttin() {
    assert_eq!(SIGTTIN, 21);
}

#[test]
fn test_sigttou() {
    assert_eq!(SIGTTOU, 22);
}

#[test]
fn test_sigurg() {
    assert_eq!(SIGURG, 23);
}

#[test]
fn test_sigxcpu() {
    assert_eq!(SIGXCPU, 24);
}

#[test]
fn test_sigxfsz() {
    assert_eq!(SIGXFSZ, 25);
}

#[test]
fn test_sigvtalrm() {
    assert_eq!(SIGVTALRM, 26);
}

#[test]
fn test_sigprof() {
    assert_eq!(SIGPROF, 27);
}

#[test]
fn test_sigwinch() {
    assert_eq!(SIGWINCH, 28);
}

#[test]
fn test_sigio() {
    assert_eq!(SIGIO, 29);
}

#[test]
fn test_sigpwr() {
    assert_eq!(SIGPWR, 30);
}

#[test]
fn test_sigsys() {
    assert_eq!(SIGSYS, 31);
}

#[test]
fn test_sigpoll_equals_sigio() {
    assert_eq!(SIGPOLL, SIGIO);
}

#[test]
fn test_sigrtmin() {
    assert_eq!(SIGRTMIN, 32);
}

#[test]
fn test_sigrtmax() {
    assert_eq!(SIGRTMAX, 64);
}

#[test]
fn test_sig_dfl() {
    assert_eq!(SIG_DFL, 0);
}

#[test]
fn test_sig_ign() {
    assert_eq!(SIG_IGN, 1);
}

#[test]
fn test_sig_err() {
    assert_eq!(SIG_ERR, u64::MAX);
}

#[test]
fn test_sa_nocldstop() {
    assert_eq!(SA_NOCLDSTOP, 0x00000001);
}

#[test]
fn test_sa_nocldwait() {
    assert_eq!(SA_NOCLDWAIT, 0x00000002);
}

#[test]
fn test_sa_siginfo() {
    assert_eq!(SA_SIGINFO, 0x00000004);
}

#[test]
fn test_sa_onstack() {
    assert_eq!(SA_ONSTACK, 0x08000000);
}

#[test]
fn test_sa_restart() {
    assert_eq!(SA_RESTART, 0x10000000);
}

#[test]
fn test_sa_nodefer() {
    assert_eq!(SA_NODEFER, 0x40000000);
}

#[test]
fn test_sa_resethand() {
    assert_eq!(SA_RESETHAND, 0x80000000);
}

#[test]
fn test_sa_restorer() {
    assert_eq!(SA_RESTORER, 0x04000000);
}

#[test]
fn test_sig_block() {
    assert_eq!(SIG_BLOCK, 0);
}

#[test]
fn test_sig_unblock() {
    assert_eq!(SIG_UNBLOCK, 1);
}

#[test]
fn test_sig_setmask() {
    assert_eq!(SIG_SETMASK, 2);
}

#[test]
fn test_sigset_new() {
    let set = SigSet::new();
    assert_eq!(set.0, 0);
    assert!(set.is_empty());
}

#[test]
fn test_sigset_full() {
    let set = SigSet::full();
    assert_eq!(set.0, !0u64);
    assert!(!set.is_empty());
}

#[test]
fn test_sigset_add() {
    let mut set = SigSet::new();
    set.add(SIGINT);
    assert!(set.contains(SIGINT));
    assert!(!set.contains(SIGTERM));
}

#[test]
fn test_sigset_add_multiple() {
    let mut set = SigSet::new();
    set.add(SIGINT);
    set.add(SIGTERM);
    set.add(SIGKILL);
    assert!(set.contains(SIGINT));
    assert!(set.contains(SIGTERM));
    assert!(set.contains(SIGKILL));
}

#[test]
fn test_sigset_remove() {
    let mut set = SigSet::new();
    set.add(SIGINT);
    set.add(SIGTERM);
    set.remove(SIGINT);
    assert!(!set.contains(SIGINT));
    assert!(set.contains(SIGTERM));
}

#[test]
fn test_sigset_contains_boundary_low() {
    let mut set = SigSet::new();
    set.add(1);
    assert!(set.contains(1));
}

#[test]
fn test_sigset_contains_boundary_high() {
    let mut set = SigSet::new();
    set.add(64);
    assert!(set.contains(64));
}

#[test]
fn test_sigset_contains_invalid_zero() {
    let set = SigSet::full();
    assert!(!set.contains(0));
}

#[test]
fn test_sigset_contains_invalid_over_64() {
    let set = SigSet::full();
    assert!(!set.contains(65));
}

#[test]
fn test_sigset_add_invalid_zero() {
    let mut set = SigSet::new();
    set.add(0);
    assert!(set.is_empty());
}

#[test]
fn test_sigset_add_invalid_over_64() {
    let mut set = SigSet::new();
    set.add(100);
    assert!(set.is_empty());
}

#[test]
fn test_sigset_not() {
    let set = SigSet::new();
    let inverted = !set;
    assert_eq!(inverted.0, !0u64);
}

#[test]
fn test_sigset_bitand() {
    let mut set1 = SigSet::new();
    set1.add(SIGINT);
    set1.add(SIGTERM);

    let mut set2 = SigSet::new();
    set2.add(SIGINT);
    set2.add(SIGKILL);

    let result = set1 & set2;
    assert!(result.contains(SIGINT));
    assert!(!result.contains(SIGTERM));
    assert!(!result.contains(SIGKILL));
}

#[test]
fn test_sigset_eq_u64() {
    let set = SigSet::new();
    assert!(set == 0u64);
}

#[test]
fn test_sigset_default() {
    let set: SigSet = Default::default();
    assert!(set.is_empty());
}

#[test]
fn test_sigset_clone() {
    let mut set = SigSet::new();
    set.add(SIGINT);
    let cloned = set.clone();
    assert!(cloned.contains(SIGINT));
}

#[test]
fn test_sigset_copy() {
    let mut set = SigSet::new();
    set.add(SIGINT);
    let copied = set;
    assert!(copied.contains(SIGINT));
}

#[test]
fn test_kernel_sigaction_default() {
    let action: KernelSigAction = Default::default();
    assert_eq!(action.handler, SIG_DFL);
    assert_eq!(action.flags, 0);
    assert_eq!(action.restorer, 0);
    assert!(action.mask.is_empty());
}

#[test]
fn test_kernel_sigaction_clone() {
    let mut action = KernelSigAction::default();
    action.handler = 0x1000;
    action.flags = SA_RESTART;
    let cloned = action.clone();
    assert_eq!(cloned.handler, 0x1000);
    assert_eq!(cloned.flags, SA_RESTART);
}

#[test]
fn test_process_signal_state_default() {
    let state: ProcessSignalState = Default::default();
    assert!(state.blocked.is_empty());
    assert!(state.pending.is_empty());
    assert!(state.pending_queue.is_empty());
    assert!(state.saved_mask.is_none());
    assert!(state.alt_stack.is_none());
}

#[test]
fn test_process_signal_state_actions_count() {
    let state = ProcessSignalState::default();
    assert_eq!(state.actions.len(), 65);
}

#[test]
fn test_pending_signal_fields() {
    let sig = PendingSignal {
        signo: SIGINT,
        code: 0,
        pid: 1234,
        uid: 1000,
        value: 0,
        timestamp: 12345678,
    };
    assert_eq!(sig.signo, SIGINT);
    assert_eq!(sig.pid, 1234);
    assert_eq!(sig.uid, 1000);
    assert_eq!(sig.timestamp, 12345678);
}

#[test]
fn test_realtime_signal_range() {
    assert!(SIGRTMIN > SIGSYS);
    assert!(SIGRTMAX >= SIGRTMIN);
    assert_eq!(SIGRTMAX - SIGRTMIN + 1, 33);
}

#[test]
fn test_standard_signals_are_less_than_32() {
    assert!(SIGHUP < 32);
    assert!(SIGINT < 32);
    assert!(SIGKILL < 32);
    assert!(SIGTERM < 32);
    assert!(SIGSYS < 32);
}

#[test]
fn test_sigkill_and_sigstop_special() {
    assert_eq!(SIGKILL, 9);
    assert_eq!(SIGSTOP, 19);
}
