// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Errno constant tests

use crate::syscall::types::errnos::*;
use crate::test::framework::TestResult;

pub(crate) fn test_eperm() -> TestResult {
    if EPERM != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enoent() -> TestResult {
    if ENOENT != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_esrch() -> TestResult {
    if ESRCH != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eintr() -> TestResult {
    if EINTR != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eio() -> TestResult {
    if EIO != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enxio() -> TestResult {
    if ENXIO != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_e2big() -> TestResult {
    if E2BIG != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enoexec() -> TestResult {
    if ENOEXEC != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ebadf() -> TestResult {
    if EBADF != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_echild() -> TestResult {
    if ECHILD != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eagain() -> TestResult {
    if EAGAIN != 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enomem() -> TestResult {
    if ENOMEM != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eacces() -> TestResult {
    if EACCES != 13 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_efault() -> TestResult {
    if EFAULT != 14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enotblk() -> TestResult {
    if ENOTBLK != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ebusy() -> TestResult {
    if EBUSY != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eexist() -> TestResult {
    if EEXIST != 17 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exdev() -> TestResult {
    if EXDEV != 18 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enodev() -> TestResult {
    if ENODEV != 19 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enotdir() -> TestResult {
    if ENOTDIR != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eisdir() -> TestResult {
    if EISDIR != 21 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_einval() -> TestResult {
    if EINVAL != 22 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enfile() -> TestResult {
    if ENFILE != 23 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_emfile() -> TestResult {
    if EMFILE != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enotty() -> TestResult {
    if ENOTTY != 25 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_etxtbsy() -> TestResult {
    if ETXTBSY != 26 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_efbig() -> TestResult {
    if EFBIG != 27 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enospc() -> TestResult {
    if ENOSPC != 28 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_espipe() -> TestResult {
    if ESPIPE != 29 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_erofs() -> TestResult {
    if EROFS != 30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_emlink() -> TestResult {
    if EMLINK != 31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_epipe() -> TestResult {
    if EPIPE != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_edom() -> TestResult {
    if EDOM != 33 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_erange() -> TestResult {
    if ERANGE != 34 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_edeadlk() -> TestResult {
    if EDEADLK != 35 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enametoolong() -> TestResult {
    if ENAMETOOLONG != 36 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enolck() -> TestResult {
    if ENOLCK != 37 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enosys() -> TestResult {
    if ENOSYS != 38 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enotempty() -> TestResult {
    if ENOTEMPTY != 39 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eloop() -> TestResult {
    if ELOOP != 40 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ewouldblock_equals_eagain() -> TestResult {
    if EWOULDBLOCK != EAGAIN {
        return TestResult::Fail;
    }
    if EWOULDBLOCK != 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_edeadlock_equals_edeadlk() -> TestResult {
    if EDEADLOCK != EDEADLK {
        return TestResult::Fail;
    }
    if EDEADLOCK != 35 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enotsock() -> TestResult {
    if ENOTSOCK != 88 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_edestaddrreq() -> TestResult {
    if EDESTADDRREQ != 89 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_emsgsize() -> TestResult {
    if EMSGSIZE != 90 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eprototype() -> TestResult {
    if EPROTOTYPE != 91 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enoprotoopt() -> TestResult {
    if ENOPROTOOPT != 92 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eprotonosupport() -> TestResult {
    if EPROTONOSUPPORT != 93 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_esocktnosupport() -> TestResult {
    if ESOCKTNOSUPPORT != 94 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eopnotsupp() -> TestResult {
    if EOPNOTSUPP != 95 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_epfnosupport() -> TestResult {
    if EPFNOSUPPORT != 96 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eafnosupport() -> TestResult {
    if EAFNOSUPPORT != 97 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eaddrinuse() -> TestResult {
    if EADDRINUSE != 98 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eaddrnotavail() -> TestResult {
    if EADDRNOTAVAIL != 99 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enetdown() -> TestResult {
    if ENETDOWN != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enetunreach() -> TestResult {
    if ENETUNREACH != 101 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enetreset() -> TestResult {
    if ENETRESET != 102 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_econnaborted() -> TestResult {
    if ECONNABORTED != 103 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_econnreset() -> TestResult {
    if ECONNRESET != 104 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enobufs() -> TestResult {
    if ENOBUFS != 105 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eisconn() -> TestResult {
    if EISCONN != 106 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enotconn() -> TestResult {
    if ENOTCONN != 107 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eshutdown() -> TestResult {
    if ESHUTDOWN != 108 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_etoomanyrefs() -> TestResult {
    if ETOOMANYREFS != 109 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_etimedout() -> TestResult {
    if ETIMEDOUT != 110 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_econnrefused() -> TestResult {
    if ECONNREFUSED != 111 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ehostdown() -> TestResult {
    if EHOSTDOWN != 112 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ehostunreach() -> TestResult {
    if EHOSTUNREACH != 113 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ealready() -> TestResult {
    if EALREADY != 114 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_einprogress() -> TestResult {
    if EINPROGRESS != 115 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_estale() -> TestResult {
    if ESTALE != 116 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ecanceled() -> TestResult {
    if ECANCELED != 125 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enokey() -> TestResult {
    if ENOKEY != 126 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ekeyexpired() -> TestResult {
    if EKEYEXPIRED != 127 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ekeyrevoked() -> TestResult {
    if EKEYREVOKED != 128 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ekeyrejected() -> TestResult {
    if EKEYREJECTED != 129 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_eownerdead() -> TestResult {
    if EOWNERDEAD != 130 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enotrecoverable() -> TestResult {
    if ENOTRECOVERABLE != 131 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_erfkill() -> TestResult {
    if ERFKILL != 132 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ehwpoison() -> TestResult {
    if EHWPOISON != 133 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_errno_values_are_positive() -> TestResult {
    if EPERM <= 0 {
        return TestResult::Fail;
    }
    if ENOENT <= 0 {
        return TestResult::Fail;
    }
    if EINVAL <= 0 {
        return TestResult::Fail;
    }
    if ENOSYS <= 0 {
        return TestResult::Fail;
    }
    if EHWPOISON <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_errno_values_unique() -> TestResult {
    let errnos = [
        EPERM,
        ENOENT,
        ESRCH,
        EINTR,
        EIO,
        ENXIO,
        E2BIG,
        ENOEXEC,
        EBADF,
        ECHILD,
        EAGAIN,
        ENOMEM,
        EACCES,
        EFAULT,
        ENOTBLK,
        EBUSY,
        EEXIST,
        EXDEV,
        ENODEV,
        ENOTDIR,
        EISDIR,
        EINVAL,
        ENFILE,
        EMFILE,
        ENOTTY,
        ETXTBSY,
        EFBIG,
        ENOSPC,
        ESPIPE,
        EROFS,
        EMLINK,
        EPIPE,
        EDOM,
        ERANGE,
        EDEADLK,
        ENAMETOOLONG,
        ENOLCK,
        ENOSYS,
        ENOTEMPTY,
        ELOOP,
    ];
    for i in 0..errnos.len() {
        for j in (i + 1)..errnos.len() {
            if errnos[i] == errnos[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_errno_range_basic() -> TestResult {
    if !(EPERM >= 1 && EPERM <= 40) {
        return TestResult::Fail;
    }
    if !(ENOENT >= 1 && ENOENT <= 40) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_errno_range_network() -> TestResult {
    if !(ENOTSOCK >= 88 && ENOTSOCK <= 133) {
        return TestResult::Fail;
    }
    if !(ECONNREFUSED >= 88 && ECONNREFUSED <= 133) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
