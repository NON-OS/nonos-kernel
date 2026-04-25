// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Syscall subsystem test suite

mod caps;
mod errnos;
mod numbers;
mod signals;
mod types;
mod validation;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("syscall");

    // Syscall result type tests
    suite.add(TestCase::new("types::syscall_result_success", types::test_syscall_result_success));
    suite.add(TestCase::new(
        "types::syscall_result_success_zero",
        types::test_syscall_result_success_zero,
    ));
    suite.add(TestCase::new(
        "types::syscall_result_success_max",
        types::test_syscall_result_success_max,
    ));
    suite.add(TestCase::new(
        "types::syscall_result_success_audited",
        types::test_syscall_result_success_audited,
    ));
    suite.add(TestCase::new("types::syscall_result_error", types::test_syscall_result_error));
    suite.add(TestCase::new(
        "types::syscall_result_error_value_is_negated",
        types::test_syscall_result_error_value_is_negated,
    ));
    suite.add(TestCase::new(
        "types::syscall_result_is_error_positive",
        types::test_syscall_result_is_error_positive,
    ));
    suite.add(TestCase::new(
        "types::syscall_result_is_error_zero",
        types::test_syscall_result_is_error_zero,
    ));
    suite.add(TestCase::new(
        "types::syscall_result_is_error_negative",
        types::test_syscall_result_is_error_negative,
    ));
    suite.add(TestCase::new(
        "types::syscall_result_errno_none_for_success",
        types::test_syscall_result_errno_none_for_success,
    ));
    suite.add(TestCase::new(
        "types::syscall_result_errno_some_for_error",
        types::test_syscall_result_errno_some_for_error,
    ));
    suite.add(TestCase::new("types::errno_helper", types::test_errno_helper));
    suite.add(TestCase::new("types::errno_helper_eperm", types::test_errno_helper_eperm));
    suite.add(TestCase::new("types::errno_helper_enoent", types::test_errno_helper_enoent));
    suite.add(TestCase::new(
        "types::syscall_result_const_success",
        types::test_syscall_result_const_success,
    ));
    suite.add(TestCase::new(
        "types::syscall_result_const_error",
        types::test_syscall_result_const_error,
    ));

    // Syscall number tests
    suite.add(TestCase::new("numbers::syscall_number_read", numbers::test_syscall_number_read));
    suite.add(TestCase::new("numbers::syscall_number_write", numbers::test_syscall_number_write));
    suite.add(TestCase::new("numbers::syscall_number_open", numbers::test_syscall_number_open));
    suite.add(TestCase::new("numbers::syscall_number_close", numbers::test_syscall_number_close));
    suite.add(TestCase::new("numbers::syscall_number_stat", numbers::test_syscall_number_stat));
    suite.add(TestCase::new("numbers::syscall_number_fstat", numbers::test_syscall_number_fstat));
    suite.add(TestCase::new("numbers::syscall_number_mmap", numbers::test_syscall_number_mmap));
    suite.add(TestCase::new(
        "numbers::syscall_number_mprotect",
        numbers::test_syscall_number_mprotect,
    ));
    suite.add(TestCase::new("numbers::syscall_number_munmap", numbers::test_syscall_number_munmap));
    suite.add(TestCase::new("numbers::syscall_number_brk", numbers::test_syscall_number_brk));
    suite.add(TestCase::new("numbers::syscall_number_fork", numbers::test_syscall_number_fork));
    suite.add(TestCase::new("numbers::syscall_number_execve", numbers::test_syscall_number_execve));
    suite.add(TestCase::new("numbers::syscall_number_exit", numbers::test_syscall_number_exit));
    suite.add(TestCase::new("numbers::syscall_number_getpid", numbers::test_syscall_number_getpid));
    suite.add(TestCase::new("numbers::syscall_number_socket", numbers::test_syscall_number_socket));
    suite.add(TestCase::new(
        "numbers::syscall_number_connect",
        numbers::test_syscall_number_connect,
    ));
    suite.add(TestCase::new("numbers::syscall_number_bind", numbers::test_syscall_number_bind));
    suite.add(TestCase::new("numbers::syscall_number_listen", numbers::test_syscall_number_listen));
    suite.add(TestCase::new(
        "numbers::syscall_number_ipc_send",
        numbers::test_syscall_number_ipc_send,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_ipc_recv",
        numbers::test_syscall_number_ipc_recv,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_ipc_create",
        numbers::test_syscall_number_ipc_create,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_ipc_destroy",
        numbers::test_syscall_number_ipc_destroy,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_crypto_random",
        numbers::test_syscall_number_crypto_random,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_crypto_hash",
        numbers::test_syscall_number_crypto_hash,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_crypto_sign",
        numbers::test_syscall_number_crypto_sign,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_crypto_verify",
        numbers::test_syscall_number_crypto_verify,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_crypto_encrypt",
        numbers::test_syscall_number_crypto_encrypt,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_crypto_decrypt",
        numbers::test_syscall_number_crypto_decrypt,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_crypto_keygen",
        numbers::test_syscall_number_crypto_keygen,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_crypto_zk_prove",
        numbers::test_syscall_number_crypto_zk_prove,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_crypto_zk_verify",
        numbers::test_syscall_number_crypto_zk_verify,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_io_port_read",
        numbers::test_syscall_number_io_port_read,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_io_port_write",
        numbers::test_syscall_number_io_port_write,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_mmio_map",
        numbers::test_syscall_number_mmio_map,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_debug_log",
        numbers::test_syscall_number_debug_log,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_admin_reboot",
        numbers::test_syscall_number_admin_reboot,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_admin_shutdown",
        numbers::test_syscall_number_admin_shutdown,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_admin_mod_load",
        numbers::test_syscall_number_admin_mod_load,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_admin_cap_grant",
        numbers::test_syscall_number_admin_cap_grant,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_admin_cap_revoke",
        numbers::test_syscall_number_admin_cap_revoke,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_invalid_returns_none",
        numbers::test_syscall_number_invalid_returns_none,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_max_u64_returns_none",
        numbers::test_syscall_number_max_u64_returns_none,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_equality",
        numbers::test_syscall_number_equality,
    ));
    suite.add(TestCase::new("numbers::syscall_number_clone", numbers::test_syscall_number_clone));
    suite.add(TestCase::new("numbers::syscall_number_copy", numbers::test_syscall_number_copy));
    suite.add(TestCase::new("numbers::syscall_number_debug", numbers::test_syscall_number_debug));
    suite.add(TestCase::new(
        "numbers::syscall_number_epoll_create",
        numbers::test_syscall_number_epoll_create,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_epoll_wait",
        numbers::test_syscall_number_epoll_wait,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_epoll_ctl",
        numbers::test_syscall_number_epoll_ctl,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_clock_gettime",
        numbers::test_syscall_number_clock_gettime,
    ));
    suite.add(TestCase::new(
        "numbers::syscall_number_nanosleep",
        numbers::test_syscall_number_nanosleep,
    ));
    suite.add(TestCase::new("numbers::syscall_number_futex", numbers::test_syscall_number_futex));
    suite.add(TestCase::new(
        "numbers::syscall_number_getrandom",
        numbers::test_syscall_number_getrandom,
    ));
    suite.add(TestCase::new("numbers::syscall_number_openat", numbers::test_syscall_number_openat));
    suite.add(TestCase::new("numbers::syscall_number_statx", numbers::test_syscall_number_statx));

    // Errno constant tests
    suite.add(TestCase::new("errnos::eperm", errnos::test_eperm));
    suite.add(TestCase::new("errnos::enoent", errnos::test_enoent));
    suite.add(TestCase::new("errnos::esrch", errnos::test_esrch));
    suite.add(TestCase::new("errnos::eintr", errnos::test_eintr));
    suite.add(TestCase::new("errnos::eio", errnos::test_eio));
    suite.add(TestCase::new("errnos::enxio", errnos::test_enxio));
    suite.add(TestCase::new("errnos::e2big", errnos::test_e2big));
    suite.add(TestCase::new("errnos::enoexec", errnos::test_enoexec));
    suite.add(TestCase::new("errnos::ebadf", errnos::test_ebadf));
    suite.add(TestCase::new("errnos::echild", errnos::test_echild));
    suite.add(TestCase::new("errnos::eagain", errnos::test_eagain));
    suite.add(TestCase::new("errnos::enomem", errnos::test_enomem));
    suite.add(TestCase::new("errnos::eacces", errnos::test_eacces));
    suite.add(TestCase::new("errnos::efault", errnos::test_efault));
    suite.add(TestCase::new("errnos::enotblk", errnos::test_enotblk));
    suite.add(TestCase::new("errnos::ebusy", errnos::test_ebusy));
    suite.add(TestCase::new("errnos::eexist", errnos::test_eexist));
    suite.add(TestCase::new("errnos::exdev", errnos::test_exdev));
    suite.add(TestCase::new("errnos::enodev", errnos::test_enodev));
    suite.add(TestCase::new("errnos::enotdir", errnos::test_enotdir));
    suite.add(TestCase::new("errnos::eisdir", errnos::test_eisdir));
    suite.add(TestCase::new("errnos::einval", errnos::test_einval));
    suite.add(TestCase::new("errnos::enfile", errnos::test_enfile));
    suite.add(TestCase::new("errnos::emfile", errnos::test_emfile));
    suite.add(TestCase::new("errnos::enotty", errnos::test_enotty));
    suite.add(TestCase::new("errnos::etxtbsy", errnos::test_etxtbsy));
    suite.add(TestCase::new("errnos::efbig", errnos::test_efbig));
    suite.add(TestCase::new("errnos::enospc", errnos::test_enospc));
    suite.add(TestCase::new("errnos::espipe", errnos::test_espipe));
    suite.add(TestCase::new("errnos::erofs", errnos::test_erofs));
    suite.add(TestCase::new("errnos::emlink", errnos::test_emlink));
    suite.add(TestCase::new("errnos::epipe", errnos::test_epipe));
    suite.add(TestCase::new("errnos::edom", errnos::test_edom));
    suite.add(TestCase::new("errnos::erange", errnos::test_erange));
    suite.add(TestCase::new("errnos::edeadlk", errnos::test_edeadlk));
    suite.add(TestCase::new("errnos::enametoolong", errnos::test_enametoolong));
    suite.add(TestCase::new("errnos::enolck", errnos::test_enolck));
    suite.add(TestCase::new("errnos::enosys", errnos::test_enosys));
    suite.add(TestCase::new("errnos::enotempty", errnos::test_enotempty));
    suite.add(TestCase::new("errnos::eloop", errnos::test_eloop));
    suite.add(TestCase::new(
        "errnos::ewouldblock_equals_eagain",
        errnos::test_ewouldblock_equals_eagain,
    ));
    suite.add(TestCase::new(
        "errnos::edeadlock_equals_edeadlk",
        errnos::test_edeadlock_equals_edeadlk,
    ));
    suite.add(TestCase::new("errnos::enotsock", errnos::test_enotsock));
    suite.add(TestCase::new("errnos::edestaddrreq", errnos::test_edestaddrreq));
    suite.add(TestCase::new("errnos::emsgsize", errnos::test_emsgsize));
    suite.add(TestCase::new("errnos::eprototype", errnos::test_eprototype));
    suite.add(TestCase::new("errnos::enoprotoopt", errnos::test_enoprotoopt));
    suite.add(TestCase::new("errnos::eprotonosupport", errnos::test_eprotonosupport));
    suite.add(TestCase::new("errnos::esocktnosupport", errnos::test_esocktnosupport));
    suite.add(TestCase::new("errnos::eopnotsupp", errnos::test_eopnotsupp));
    suite.add(TestCase::new("errnos::epfnosupport", errnos::test_epfnosupport));
    suite.add(TestCase::new("errnos::eafnosupport", errnos::test_eafnosupport));
    suite.add(TestCase::new("errnos::eaddrinuse", errnos::test_eaddrinuse));
    suite.add(TestCase::new("errnos::eaddrnotavail", errnos::test_eaddrnotavail));
    suite.add(TestCase::new("errnos::enetdown", errnos::test_enetdown));
    suite.add(TestCase::new("errnos::enetunreach", errnos::test_enetunreach));
    suite.add(TestCase::new("errnos::enetreset", errnos::test_enetreset));
    suite.add(TestCase::new("errnos::econnaborted", errnos::test_econnaborted));
    suite.add(TestCase::new("errnos::econnreset", errnos::test_econnreset));
    suite.add(TestCase::new("errnos::enobufs", errnos::test_enobufs));
    suite.add(TestCase::new("errnos::eisconn", errnos::test_eisconn));
    suite.add(TestCase::new("errnos::enotconn", errnos::test_enotconn));
    suite.add(TestCase::new("errnos::eshutdown", errnos::test_eshutdown));
    suite.add(TestCase::new("errnos::etoomanyrefs", errnos::test_etoomanyrefs));
    suite.add(TestCase::new("errnos::etimedout", errnos::test_etimedout));
    suite.add(TestCase::new("errnos::econnrefused", errnos::test_econnrefused));
    suite.add(TestCase::new("errnos::ehostdown", errnos::test_ehostdown));
    suite.add(TestCase::new("errnos::ehostunreach", errnos::test_ehostunreach));
    suite.add(TestCase::new("errnos::ealready", errnos::test_ealready));
    suite.add(TestCase::new("errnos::einprogress", errnos::test_einprogress));
    suite.add(TestCase::new("errnos::estale", errnos::test_estale));
    suite.add(TestCase::new("errnos::ecanceled", errnos::test_ecanceled));
    suite.add(TestCase::new("errnos::enokey", errnos::test_enokey));
    suite.add(TestCase::new("errnos::ekeyexpired", errnos::test_ekeyexpired));
    suite.add(TestCase::new("errnos::ekeyrevoked", errnos::test_ekeyrevoked));
    suite.add(TestCase::new("errnos::ekeyrejected", errnos::test_ekeyrejected));
    suite.add(TestCase::new("errnos::eownerdead", errnos::test_eownerdead));
    suite.add(TestCase::new("errnos::enotrecoverable", errnos::test_enotrecoverable));
    suite.add(TestCase::new("errnos::erfkill", errnos::test_erfkill));
    suite.add(TestCase::new("errnos::ehwpoison", errnos::test_ehwpoison));
    suite.add(TestCase::new(
        "errnos::errno_values_are_positive",
        errnos::test_errno_values_are_positive,
    ));
    suite.add(TestCase::new("errnos::errno_values_unique", errnos::test_errno_values_unique));
    suite.add(TestCase::new("errnos::errno_range_basic", errnos::test_errno_range_basic));
    suite.add(TestCase::new("errnos::errno_range_network", errnos::test_errno_range_network));

    // Signal constant and type tests
    suite.add(TestCase::new("signals::sighup", signals::test_sighup));
    suite.add(TestCase::new("signals::sigint", signals::test_sigint));
    suite.add(TestCase::new("signals::sigquit", signals::test_sigquit));
    suite.add(TestCase::new("signals::sigill", signals::test_sigill));
    suite.add(TestCase::new("signals::sigtrap", signals::test_sigtrap));
    suite.add(TestCase::new("signals::sigabrt", signals::test_sigabrt));
    suite.add(TestCase::new("signals::sigbus", signals::test_sigbus));
    suite.add(TestCase::new("signals::sigfpe", signals::test_sigfpe));
    suite.add(TestCase::new("signals::sigkill", signals::test_sigkill));
    suite.add(TestCase::new("signals::sigusr1", signals::test_sigusr1));
    suite.add(TestCase::new("signals::sigsegv", signals::test_sigsegv));
    suite.add(TestCase::new("signals::sigusr2", signals::test_sigusr2));
    suite.add(TestCase::new("signals::sigpipe", signals::test_sigpipe));
    suite.add(TestCase::new("signals::sigalrm", signals::test_sigalrm));
    suite.add(TestCase::new("signals::sigterm", signals::test_sigterm));
    suite.add(TestCase::new("signals::sigstkflt", signals::test_sigstkflt));
    suite.add(TestCase::new("signals::sigchld", signals::test_sigchld));
    suite.add(TestCase::new("signals::sigcont", signals::test_sigcont));
    suite.add(TestCase::new("signals::sigstop", signals::test_sigstop));
    suite.add(TestCase::new("signals::sigtstp", signals::test_sigtstp));
    suite.add(TestCase::new("signals::sigttin", signals::test_sigttin));
    suite.add(TestCase::new("signals::sigttou", signals::test_sigttou));
    suite.add(TestCase::new("signals::sigurg", signals::test_sigurg));
    suite.add(TestCase::new("signals::sigxcpu", signals::test_sigxcpu));
    suite.add(TestCase::new("signals::sigxfsz", signals::test_sigxfsz));
    suite.add(TestCase::new("signals::sigvtalrm", signals::test_sigvtalrm));
    suite.add(TestCase::new("signals::sigprof", signals::test_sigprof));
    suite.add(TestCase::new("signals::sigwinch", signals::test_sigwinch));
    suite.add(TestCase::new("signals::sigio", signals::test_sigio));
    suite.add(TestCase::new("signals::sigpwr", signals::test_sigpwr));
    suite.add(TestCase::new("signals::sigsys", signals::test_sigsys));
    suite.add(TestCase::new("signals::sigpoll_equals_sigio", signals::test_sigpoll_equals_sigio));
    suite.add(TestCase::new("signals::sigrtmin", signals::test_sigrtmin));
    suite.add(TestCase::new("signals::sigrtmax", signals::test_sigrtmax));
    suite.add(TestCase::new("signals::sig_dfl", signals::test_sig_dfl));
    suite.add(TestCase::new("signals::sig_ign", signals::test_sig_ign));
    suite.add(TestCase::new("signals::sig_err", signals::test_sig_err));
    suite.add(TestCase::new("signals::sa_nocldstop", signals::test_sa_nocldstop));
    suite.add(TestCase::new("signals::sa_nocldwait", signals::test_sa_nocldwait));
    suite.add(TestCase::new("signals::sa_siginfo", signals::test_sa_siginfo));
    suite.add(TestCase::new("signals::sa_onstack", signals::test_sa_onstack));
    suite.add(TestCase::new("signals::sa_restart", signals::test_sa_restart));
    suite.add(TestCase::new("signals::sa_nodefer", signals::test_sa_nodefer));
    suite.add(TestCase::new("signals::sa_resethand", signals::test_sa_resethand));
    suite.add(TestCase::new("signals::sa_restorer", signals::test_sa_restorer));
    suite.add(TestCase::new("signals::sig_block", signals::test_sig_block));
    suite.add(TestCase::new("signals::sig_unblock", signals::test_sig_unblock));
    suite.add(TestCase::new("signals::sig_setmask", signals::test_sig_setmask));
    suite.add(TestCase::new("signals::sigset_new", signals::test_sigset_new));
    suite.add(TestCase::new("signals::sigset_full", signals::test_sigset_full));
    suite.add(TestCase::new("signals::sigset_add", signals::test_sigset_add));
    suite.add(TestCase::new("signals::sigset_add_multiple", signals::test_sigset_add_multiple));
    suite.add(TestCase::new("signals::sigset_remove", signals::test_sigset_remove));
    suite.add(TestCase::new(
        "signals::sigset_contains_boundary_low",
        signals::test_sigset_contains_boundary_low,
    ));
    suite.add(TestCase::new(
        "signals::sigset_contains_boundary_high",
        signals::test_sigset_contains_boundary_high,
    ));
    suite.add(TestCase::new(
        "signals::sigset_contains_invalid_zero",
        signals::test_sigset_contains_invalid_zero,
    ));
    suite.add(TestCase::new(
        "signals::sigset_contains_invalid_over_64",
        signals::test_sigset_contains_invalid_over_64,
    ));
    suite.add(TestCase::new(
        "signals::sigset_add_invalid_zero",
        signals::test_sigset_add_invalid_zero,
    ));
    suite.add(TestCase::new(
        "signals::sigset_add_invalid_over_64",
        signals::test_sigset_add_invalid_over_64,
    ));
    suite.add(TestCase::new("signals::sigset_not", signals::test_sigset_not));
    suite.add(TestCase::new("signals::sigset_bitand", signals::test_sigset_bitand));
    suite.add(TestCase::new("signals::sigset_eq_u64", signals::test_sigset_eq_u64));
    suite.add(TestCase::new("signals::sigset_default", signals::test_sigset_default));
    suite.add(TestCase::new("signals::sigset_clone", signals::test_sigset_clone));
    suite.add(TestCase::new("signals::sigset_copy", signals::test_sigset_copy));
    suite.add(TestCase::new(
        "signals::kernel_sigaction_default",
        signals::test_kernel_sigaction_default,
    ));
    suite.add(TestCase::new(
        "signals::kernel_sigaction_clone",
        signals::test_kernel_sigaction_clone,
    ));
    suite.add(TestCase::new(
        "signals::process_signal_state_default",
        signals::test_process_signal_state_default,
    ));
    suite.add(TestCase::new(
        "signals::process_signal_state_actions_count",
        signals::test_process_signal_state_actions_count,
    ));
    suite.add(TestCase::new("signals::pending_signal_fields", signals::test_pending_signal_fields));
    suite.add(TestCase::new("signals::realtime_signal_range", signals::test_realtime_signal_range));
    suite.add(TestCase::new(
        "signals::standard_signals_are_less_than_32",
        signals::test_standard_signals_are_less_than_32,
    ));
    suite.add(TestCase::new(
        "signals::sigkill_and_sigstop_special",
        signals::test_sigkill_and_sigstop_special,
    ));

    // Capability token syscall permission tests
    suite.add(TestCase::new(
        "caps::capability_token_can_exit_requires_core_exec",
        caps::test_capability_token_can_exit_requires_core_exec,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_exit_without_core_exec",
        caps::test_capability_token_can_exit_without_core_exec,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_getpid",
        caps::test_capability_token_can_getpid,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_fork",
        caps::test_capability_token_can_fork,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_exec",
        caps::test_capability_token_can_exec,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_wait",
        caps::test_capability_token_can_wait,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_signal",
        caps::test_capability_token_can_signal,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_read",
        caps::test_capability_token_can_read,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_read_without_io",
        caps::test_capability_token_can_read_without_io,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_write",
        caps::test_capability_token_can_write,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_open_files",
        caps::test_capability_token_can_open_files,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_close_files",
        caps::test_capability_token_can_close_files,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_stat",
        caps::test_capability_token_can_stat,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_seek",
        caps::test_capability_token_can_seek,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_modify_dirs",
        caps::test_capability_token_can_modify_dirs,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_unlink",
        caps::test_capability_token_can_unlink,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_allocate_memory",
        caps::test_capability_token_can_allocate_memory,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_deallocate_memory",
        caps::test_capability_token_can_deallocate_memory,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_network",
        caps::test_capability_token_can_network,
    ));
    suite.add(TestCase::new("caps::capability_token_can_ipc", caps::test_capability_token_can_ipc));
    suite.add(TestCase::new(
        "caps::capability_token_can_crypto",
        caps::test_capability_token_can_crypto,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_hardware",
        caps::test_capability_token_can_hardware,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_debug",
        caps::test_capability_token_can_debug,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_can_admin",
        caps::test_capability_token_can_admin,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_empty_cannot_do_anything",
        caps::test_capability_token_empty_cannot_do_anything,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_multiple_capabilities",
        caps::test_capability_token_multiple_capabilities,
    ));
    suite.add(TestCase::new(
        "caps::capability_token_all_capabilities",
        caps::test_capability_token_all_capabilities,
    ));

    // Validation tests
    suite.add(TestCase::new("validation::module_exists", validation::test_module_exists));
    suite.add(TestCase::new("validation::basic_constants", validation::test_basic_constants));
    suite.add(TestCase::new("validation::basic_operations", validation::test_basic_operations));

    suite.run()
}
