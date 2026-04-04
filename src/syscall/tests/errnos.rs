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

use crate::syscall::types::errnos::*;

#[test]
fn test_eperm() {
    assert_eq!(EPERM, 1);
}

#[test]
fn test_enoent() {
    assert_eq!(ENOENT, 2);
}

#[test]
fn test_esrch() {
    assert_eq!(ESRCH, 3);
}

#[test]
fn test_eintr() {
    assert_eq!(EINTR, 4);
}

#[test]
fn test_eio() {
    assert_eq!(EIO, 5);
}

#[test]
fn test_enxio() {
    assert_eq!(ENXIO, 6);
}

#[test]
fn test_e2big() {
    assert_eq!(E2BIG, 7);
}

#[test]
fn test_enoexec() {
    assert_eq!(ENOEXEC, 8);
}

#[test]
fn test_ebadf() {
    assert_eq!(EBADF, 9);
}

#[test]
fn test_echild() {
    assert_eq!(ECHILD, 10);
}

#[test]
fn test_eagain() {
    assert_eq!(EAGAIN, 11);
}

#[test]
fn test_enomem() {
    assert_eq!(ENOMEM, 12);
}

#[test]
fn test_eacces() {
    assert_eq!(EACCES, 13);
}

#[test]
fn test_efault() {
    assert_eq!(EFAULT, 14);
}

#[test]
fn test_enotblk() {
    assert_eq!(ENOTBLK, 15);
}

#[test]
fn test_ebusy() {
    assert_eq!(EBUSY, 16);
}

#[test]
fn test_eexist() {
    assert_eq!(EEXIST, 17);
}

#[test]
fn test_exdev() {
    assert_eq!(EXDEV, 18);
}

#[test]
fn test_enodev() {
    assert_eq!(ENODEV, 19);
}

#[test]
fn test_enotdir() {
    assert_eq!(ENOTDIR, 20);
}

#[test]
fn test_eisdir() {
    assert_eq!(EISDIR, 21);
}

#[test]
fn test_einval() {
    assert_eq!(EINVAL, 22);
}

#[test]
fn test_enfile() {
    assert_eq!(ENFILE, 23);
}

#[test]
fn test_emfile() {
    assert_eq!(EMFILE, 24);
}

#[test]
fn test_enotty() {
    assert_eq!(ENOTTY, 25);
}

#[test]
fn test_etxtbsy() {
    assert_eq!(ETXTBSY, 26);
}

#[test]
fn test_efbig() {
    assert_eq!(EFBIG, 27);
}

#[test]
fn test_enospc() {
    assert_eq!(ENOSPC, 28);
}

#[test]
fn test_espipe() {
    assert_eq!(ESPIPE, 29);
}

#[test]
fn test_erofs() {
    assert_eq!(EROFS, 30);
}

#[test]
fn test_emlink() {
    assert_eq!(EMLINK, 31);
}

#[test]
fn test_epipe() {
    assert_eq!(EPIPE, 32);
}

#[test]
fn test_edom() {
    assert_eq!(EDOM, 33);
}

#[test]
fn test_erange() {
    assert_eq!(ERANGE, 34);
}

#[test]
fn test_edeadlk() {
    assert_eq!(EDEADLK, 35);
}

#[test]
fn test_enametoolong() {
    assert_eq!(ENAMETOOLONG, 36);
}

#[test]
fn test_enolck() {
    assert_eq!(ENOLCK, 37);
}

#[test]
fn test_enosys() {
    assert_eq!(ENOSYS, 38);
}

#[test]
fn test_enotempty() {
    assert_eq!(ENOTEMPTY, 39);
}

#[test]
fn test_eloop() {
    assert_eq!(ELOOP, 40);
}

#[test]
fn test_ewouldblock_equals_eagain() {
    assert_eq!(EWOULDBLOCK, EAGAIN);
    assert_eq!(EWOULDBLOCK, 11);
}

#[test]
fn test_edeadlock_equals_edeadlk() {
    assert_eq!(EDEADLOCK, EDEADLK);
    assert_eq!(EDEADLOCK, 35);
}

#[test]
fn test_enotsock() {
    assert_eq!(ENOTSOCK, 88);
}

#[test]
fn test_edestaddrreq() {
    assert_eq!(EDESTADDRREQ, 89);
}

#[test]
fn test_emsgsize() {
    assert_eq!(EMSGSIZE, 90);
}

#[test]
fn test_eprototype() {
    assert_eq!(EPROTOTYPE, 91);
}

#[test]
fn test_enoprotoopt() {
    assert_eq!(ENOPROTOOPT, 92);
}

#[test]
fn test_eprotonosupport() {
    assert_eq!(EPROTONOSUPPORT, 93);
}

#[test]
fn test_esocktnosupport() {
    assert_eq!(ESOCKTNOSUPPORT, 94);
}

#[test]
fn test_eopnotsupp() {
    assert_eq!(EOPNOTSUPP, 95);
}

#[test]
fn test_epfnosupport() {
    assert_eq!(EPFNOSUPPORT, 96);
}

#[test]
fn test_eafnosupport() {
    assert_eq!(EAFNOSUPPORT, 97);
}

#[test]
fn test_eaddrinuse() {
    assert_eq!(EADDRINUSE, 98);
}

#[test]
fn test_eaddrnotavail() {
    assert_eq!(EADDRNOTAVAIL, 99);
}

#[test]
fn test_enetdown() {
    assert_eq!(ENETDOWN, 100);
}

#[test]
fn test_enetunreach() {
    assert_eq!(ENETUNREACH, 101);
}

#[test]
fn test_enetreset() {
    assert_eq!(ENETRESET, 102);
}

#[test]
fn test_econnaborted() {
    assert_eq!(ECONNABORTED, 103);
}

#[test]
fn test_econnreset() {
    assert_eq!(ECONNRESET, 104);
}

#[test]
fn test_enobufs() {
    assert_eq!(ENOBUFS, 105);
}

#[test]
fn test_eisconn() {
    assert_eq!(EISCONN, 106);
}

#[test]
fn test_enotconn() {
    assert_eq!(ENOTCONN, 107);
}

#[test]
fn test_eshutdown() {
    assert_eq!(ESHUTDOWN, 108);
}

#[test]
fn test_etoomanyrefs() {
    assert_eq!(ETOOMANYREFS, 109);
}

#[test]
fn test_etimedout() {
    assert_eq!(ETIMEDOUT, 110);
}

#[test]
fn test_econnrefused() {
    assert_eq!(ECONNREFUSED, 111);
}

#[test]
fn test_ehostdown() {
    assert_eq!(EHOSTDOWN, 112);
}

#[test]
fn test_ehostunreach() {
    assert_eq!(EHOSTUNREACH, 113);
}

#[test]
fn test_ealready() {
    assert_eq!(EALREADY, 114);
}

#[test]
fn test_einprogress() {
    assert_eq!(EINPROGRESS, 115);
}

#[test]
fn test_estale() {
    assert_eq!(ESTALE, 116);
}

#[test]
fn test_ecanceled() {
    assert_eq!(ECANCELED, 125);
}

#[test]
fn test_enokey() {
    assert_eq!(ENOKEY, 126);
}

#[test]
fn test_ekeyexpired() {
    assert_eq!(EKEYEXPIRED, 127);
}

#[test]
fn test_ekeyrevoked() {
    assert_eq!(EKEYREVOKED, 128);
}

#[test]
fn test_ekeyrejected() {
    assert_eq!(EKEYREJECTED, 129);
}

#[test]
fn test_eownerdead() {
    assert_eq!(EOWNERDEAD, 130);
}

#[test]
fn test_enotrecoverable() {
    assert_eq!(ENOTRECOVERABLE, 131);
}

#[test]
fn test_erfkill() {
    assert_eq!(ERFKILL, 132);
}

#[test]
fn test_ehwpoison() {
    assert_eq!(EHWPOISON, 133);
}

#[test]
fn test_errno_values_are_positive() {
    assert!(EPERM > 0);
    assert!(ENOENT > 0);
    assert!(EINVAL > 0);
    assert!(ENOSYS > 0);
    assert!(EHWPOISON > 0);
}

#[test]
fn test_errno_values_unique() {
    let errnos = [
        EPERM, ENOENT, ESRCH, EINTR, EIO, ENXIO, E2BIG, ENOEXEC, EBADF, ECHILD,
        EAGAIN, ENOMEM, EACCES, EFAULT, ENOTBLK, EBUSY, EEXIST, EXDEV, ENODEV,
        ENOTDIR, EISDIR, EINVAL, ENFILE, EMFILE, ENOTTY, ETXTBSY, EFBIG, ENOSPC,
        ESPIPE, EROFS, EMLINK, EPIPE, EDOM, ERANGE, EDEADLK, ENAMETOOLONG, ENOLCK,
        ENOSYS, ENOTEMPTY, ELOOP,
    ];
    for i in 0..errnos.len() {
        for j in (i + 1)..errnos.len() {
            assert_ne!(errnos[i], errnos[j]);
        }
    }
}

#[test]
fn test_errno_range_basic() {
    assert!(EPERM >= 1 && EPERM <= 40);
    assert!(ENOENT >= 1 && ENOENT <= 40);
}

#[test]
fn test_errno_range_network() {
    assert!(ENOTSOCK >= 88 && ENOTSOCK <= 133);
    assert!(ECONNREFUSED >= 88 && ECONNREFUSED <= 133);
}
