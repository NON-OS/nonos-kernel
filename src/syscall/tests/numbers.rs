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

use crate::syscall::numbers::*;

#[test]
fn test_syscall_number_read() {
    assert_eq!(SyscallNumber::Read as u64, 0);
    assert_eq!(SyscallNumber::from_u64(0), Some(SyscallNumber::Read));
}

#[test]
fn test_syscall_number_write() {
    assert_eq!(SyscallNumber::Write as u64, 1);
    assert_eq!(SyscallNumber::from_u64(1), Some(SyscallNumber::Write));
}

#[test]
fn test_syscall_number_open() {
    assert_eq!(SyscallNumber::Open as u64, 2);
    assert_eq!(SyscallNumber::from_u64(2), Some(SyscallNumber::Open));
}

#[test]
fn test_syscall_number_close() {
    assert_eq!(SyscallNumber::Close as u64, 3);
    assert_eq!(SyscallNumber::from_u64(3), Some(SyscallNumber::Close));
}

#[test]
fn test_syscall_number_stat() {
    assert_eq!(SyscallNumber::Stat as u64, 4);
    assert_eq!(SyscallNumber::from_u64(4), Some(SyscallNumber::Stat));
}

#[test]
fn test_syscall_number_fstat() {
    assert_eq!(SyscallNumber::Fstat as u64, 5);
    assert_eq!(SyscallNumber::from_u64(5), Some(SyscallNumber::Fstat));
}

#[test]
fn test_syscall_number_mmap() {
    assert_eq!(SyscallNumber::Mmap as u64, 9);
    assert_eq!(SyscallNumber::from_u64(9), Some(SyscallNumber::Mmap));
}

#[test]
fn test_syscall_number_mprotect() {
    assert_eq!(SyscallNumber::Mprotect as u64, 10);
    assert_eq!(SyscallNumber::from_u64(10), Some(SyscallNumber::Mprotect));
}

#[test]
fn test_syscall_number_munmap() {
    assert_eq!(SyscallNumber::Munmap as u64, 11);
    assert_eq!(SyscallNumber::from_u64(11), Some(SyscallNumber::Munmap));
}

#[test]
fn test_syscall_number_brk() {
    assert_eq!(SyscallNumber::Brk as u64, 12);
    assert_eq!(SyscallNumber::from_u64(12), Some(SyscallNumber::Brk));
}

#[test]
fn test_syscall_number_fork() {
    assert_eq!(SyscallNumber::Fork as u64, 57);
    assert_eq!(SyscallNumber::from_u64(57), Some(SyscallNumber::Fork));
}

#[test]
fn test_syscall_number_execve() {
    assert_eq!(SyscallNumber::Execve as u64, 59);
    assert_eq!(SyscallNumber::from_u64(59), Some(SyscallNumber::Execve));
}

#[test]
fn test_syscall_number_exit() {
    assert_eq!(SyscallNumber::Exit as u64, 60);
    assert_eq!(SyscallNumber::from_u64(60), Some(SyscallNumber::Exit));
}

#[test]
fn test_syscall_number_getpid() {
    assert_eq!(SyscallNumber::Getpid as u64, 39);
    assert_eq!(SyscallNumber::from_u64(39), Some(SyscallNumber::Getpid));
}

#[test]
fn test_syscall_number_socket() {
    assert_eq!(SyscallNumber::Socket as u64, 41);
    assert_eq!(SyscallNumber::from_u64(41), Some(SyscallNumber::Socket));
}

#[test]
fn test_syscall_number_connect() {
    assert_eq!(SyscallNumber::Connect as u64, 42);
    assert_eq!(SyscallNumber::from_u64(42), Some(SyscallNumber::Connect));
}

#[test]
fn test_syscall_number_bind() {
    assert_eq!(SyscallNumber::Bind as u64, 49);
    assert_eq!(SyscallNumber::from_u64(49), Some(SyscallNumber::Bind));
}

#[test]
fn test_syscall_number_listen() {
    assert_eq!(SyscallNumber::Listen as u64, 50);
    assert_eq!(SyscallNumber::from_u64(50), Some(SyscallNumber::Listen));
}

#[test]
fn test_syscall_number_ipc_send() {
    assert_eq!(SyscallNumber::IpcSend as u64, 800);
    assert_eq!(SyscallNumber::from_u64(800), Some(SyscallNumber::IpcSend));
}

#[test]
fn test_syscall_number_ipc_recv() {
    assert_eq!(SyscallNumber::IpcRecv as u64, 801);
    assert_eq!(SyscallNumber::from_u64(801), Some(SyscallNumber::IpcRecv));
}

#[test]
fn test_syscall_number_ipc_create() {
    assert_eq!(SyscallNumber::IpcCreate as u64, 802);
    assert_eq!(SyscallNumber::from_u64(802), Some(SyscallNumber::IpcCreate));
}

#[test]
fn test_syscall_number_ipc_destroy() {
    assert_eq!(SyscallNumber::IpcDestroy as u64, 803);
    assert_eq!(SyscallNumber::from_u64(803), Some(SyscallNumber::IpcDestroy));
}

#[test]
fn test_syscall_number_crypto_random() {
    assert_eq!(SyscallNumber::CryptoRandom as u64, 900);
    assert_eq!(SyscallNumber::from_u64(900), Some(SyscallNumber::CryptoRandom));
}

#[test]
fn test_syscall_number_crypto_hash() {
    assert_eq!(SyscallNumber::CryptoHash as u64, 901);
    assert_eq!(SyscallNumber::from_u64(901), Some(SyscallNumber::CryptoHash));
}

#[test]
fn test_syscall_number_crypto_sign() {
    assert_eq!(SyscallNumber::CryptoSign as u64, 902);
    assert_eq!(SyscallNumber::from_u64(902), Some(SyscallNumber::CryptoSign));
}

#[test]
fn test_syscall_number_crypto_verify() {
    assert_eq!(SyscallNumber::CryptoVerify as u64, 903);
    assert_eq!(SyscallNumber::from_u64(903), Some(SyscallNumber::CryptoVerify));
}

#[test]
fn test_syscall_number_crypto_encrypt() {
    assert_eq!(SyscallNumber::CryptoEncrypt as u64, 904);
    assert_eq!(SyscallNumber::from_u64(904), Some(SyscallNumber::CryptoEncrypt));
}

#[test]
fn test_syscall_number_crypto_decrypt() {
    assert_eq!(SyscallNumber::CryptoDecrypt as u64, 905);
    assert_eq!(SyscallNumber::from_u64(905), Some(SyscallNumber::CryptoDecrypt));
}

#[test]
fn test_syscall_number_crypto_keygen() {
    assert_eq!(SyscallNumber::CryptoKeyGen as u64, 906);
    assert_eq!(SyscallNumber::from_u64(906), Some(SyscallNumber::CryptoKeyGen));
}

#[test]
fn test_syscall_number_crypto_zk_prove() {
    assert_eq!(SyscallNumber::CryptoZkProve as u64, 907);
    assert_eq!(SyscallNumber::from_u64(907), Some(SyscallNumber::CryptoZkProve));
}

#[test]
fn test_syscall_number_crypto_zk_verify() {
    assert_eq!(SyscallNumber::CryptoZkVerify as u64, 908);
    assert_eq!(SyscallNumber::from_u64(908), Some(SyscallNumber::CryptoZkVerify));
}

#[test]
fn test_syscall_number_io_port_read() {
    assert_eq!(SyscallNumber::IoPortRead as u64, 1000);
    assert_eq!(SyscallNumber::from_u64(1000), Some(SyscallNumber::IoPortRead));
}

#[test]
fn test_syscall_number_io_port_write() {
    assert_eq!(SyscallNumber::IoPortWrite as u64, 1001);
    assert_eq!(SyscallNumber::from_u64(1001), Some(SyscallNumber::IoPortWrite));
}

#[test]
fn test_syscall_number_mmio_map() {
    assert_eq!(SyscallNumber::MmioMap as u64, 1002);
    assert_eq!(SyscallNumber::from_u64(1002), Some(SyscallNumber::MmioMap));
}

#[test]
fn test_syscall_number_debug_log() {
    assert_eq!(SyscallNumber::DebugLog as u64, 1100);
    assert_eq!(SyscallNumber::from_u64(1100), Some(SyscallNumber::DebugLog));
}

#[test]
fn test_syscall_number_admin_reboot() {
    assert_eq!(SyscallNumber::AdminReboot as u64, 1200);
    assert_eq!(SyscallNumber::from_u64(1200), Some(SyscallNumber::AdminReboot));
}

#[test]
fn test_syscall_number_admin_shutdown() {
    assert_eq!(SyscallNumber::AdminShutdown as u64, 1201);
    assert_eq!(SyscallNumber::from_u64(1201), Some(SyscallNumber::AdminShutdown));
}

#[test]
fn test_syscall_number_admin_mod_load() {
    assert_eq!(SyscallNumber::AdminModLoad as u64, 1202);
    assert_eq!(SyscallNumber::from_u64(1202), Some(SyscallNumber::AdminModLoad));
}

#[test]
fn test_syscall_number_admin_cap_grant() {
    assert_eq!(SyscallNumber::AdminCapGrant as u64, 1203);
    assert_eq!(SyscallNumber::from_u64(1203), Some(SyscallNumber::AdminCapGrant));
}

#[test]
fn test_syscall_number_admin_cap_revoke() {
    assert_eq!(SyscallNumber::AdminCapRevoke as u64, 1204);
    assert_eq!(SyscallNumber::from_u64(1204), Some(SyscallNumber::AdminCapRevoke));
}

#[test]
fn test_syscall_number_invalid_returns_none() {
    assert_eq!(SyscallNumber::from_u64(9999), None);
}

#[test]
fn test_syscall_number_max_u64_returns_none() {
    assert_eq!(SyscallNumber::from_u64(u64::MAX), None);
}

#[test]
fn test_syscall_number_equality() {
    assert_eq!(SyscallNumber::Read, SyscallNumber::Read);
    assert_ne!(SyscallNumber::Read, SyscallNumber::Write);
}

#[test]
fn test_syscall_number_clone() {
    let num = SyscallNumber::Read;
    let cloned = num.clone();
    assert_eq!(num, cloned);
}

#[test]
fn test_syscall_number_copy() {
    let num = SyscallNumber::Write;
    let copied = num;
    assert_eq!(num, copied);
}

#[test]
fn test_syscall_number_debug() {
    let num = SyscallNumber::Exit;
    let debug_str = format!("{:?}", num);
    assert!(debug_str.contains("Exit"));
}

#[test]
fn test_syscall_number_epoll_create() {
    assert_eq!(SyscallNumber::EpollCreate as u64, 213);
    assert_eq!(SyscallNumber::from_u64(213), Some(SyscallNumber::EpollCreate));
}

#[test]
fn test_syscall_number_epoll_wait() {
    assert_eq!(SyscallNumber::EpollWait as u64, 232);
    assert_eq!(SyscallNumber::from_u64(232), Some(SyscallNumber::EpollWait));
}

#[test]
fn test_syscall_number_epoll_ctl() {
    assert_eq!(SyscallNumber::EpollCtl as u64, 233);
    assert_eq!(SyscallNumber::from_u64(233), Some(SyscallNumber::EpollCtl));
}

#[test]
fn test_syscall_number_clock_gettime() {
    assert_eq!(SyscallNumber::ClockGettime as u64, 228);
    assert_eq!(SyscallNumber::from_u64(228), Some(SyscallNumber::ClockGettime));
}

#[test]
fn test_syscall_number_nanosleep() {
    assert_eq!(SyscallNumber::Nanosleep as u64, 35);
    assert_eq!(SyscallNumber::from_u64(35), Some(SyscallNumber::Nanosleep));
}

#[test]
fn test_syscall_number_futex() {
    assert_eq!(SyscallNumber::Futex as u64, 202);
    assert_eq!(SyscallNumber::from_u64(202), Some(SyscallNumber::Futex));
}

#[test]
fn test_syscall_number_getrandom() {
    assert_eq!(SyscallNumber::Getrandom as u64, 318);
    assert_eq!(SyscallNumber::from_u64(318), Some(SyscallNumber::Getrandom));
}

#[test]
fn test_syscall_number_openat() {
    assert_eq!(SyscallNumber::Openat as u64, 257);
    assert_eq!(SyscallNumber::from_u64(257), Some(SyscallNumber::Openat));
}

#[test]
fn test_syscall_number_statx() {
    assert_eq!(SyscallNumber::Statx as u64, 332);
    assert_eq!(SyscallNumber::from_u64(332), Some(SyscallNumber::Statx));
}
