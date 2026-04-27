// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Syscall number tests

extern crate alloc;

use crate::syscall::numbers::*;
use crate::test::framework::TestResult;
use alloc::format;

pub(crate) fn test_syscall_number_read() -> TestResult {
    if SyscallNumber::Read as u64 != 0 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(0) != Some(SyscallNumber::Read) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_write() -> TestResult {
    if SyscallNumber::Write as u64 != 1 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(1) != Some(SyscallNumber::Write) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_open() -> TestResult {
    if SyscallNumber::Open as u64 != 2 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(2) != Some(SyscallNumber::Open) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_close() -> TestResult {
    if SyscallNumber::Close as u64 != 3 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(3) != Some(SyscallNumber::Close) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_stat() -> TestResult {
    if SyscallNumber::Stat as u64 != 4 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(4) != Some(SyscallNumber::Stat) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_fstat() -> TestResult {
    if SyscallNumber::Fstat as u64 != 5 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(5) != Some(SyscallNumber::Fstat) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_mmap() -> TestResult {
    if SyscallNumber::Mmap as u64 != 9 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(9) != Some(SyscallNumber::Mmap) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_mprotect() -> TestResult {
    if SyscallNumber::Mprotect as u64 != 10 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(10) != Some(SyscallNumber::Mprotect) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_munmap() -> TestResult {
    if SyscallNumber::Munmap as u64 != 11 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(11) != Some(SyscallNumber::Munmap) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_brk() -> TestResult {
    if SyscallNumber::Brk as u64 != 12 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(12) != Some(SyscallNumber::Brk) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_fork() -> TestResult {
    if SyscallNumber::Fork as u64 != 57 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(57) != Some(SyscallNumber::Fork) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_execve() -> TestResult {
    if SyscallNumber::Execve as u64 != 59 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(59) != Some(SyscallNumber::Execve) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_exit() -> TestResult {
    if SyscallNumber::Exit as u64 != 60 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(60) != Some(SyscallNumber::Exit) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_getpid() -> TestResult {
    if SyscallNumber::Getpid as u64 != 39 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(39) != Some(SyscallNumber::Getpid) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_socket() -> TestResult {
    if SyscallNumber::Socket as u64 != 41 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(41) != Some(SyscallNumber::Socket) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_connect() -> TestResult {
    if SyscallNumber::Connect as u64 != 42 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(42) != Some(SyscallNumber::Connect) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_bind() -> TestResult {
    if SyscallNumber::Bind as u64 != 49 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(49) != Some(SyscallNumber::Bind) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_listen() -> TestResult {
    if SyscallNumber::Listen as u64 != 50 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(50) != Some(SyscallNumber::Listen) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_ipc_send() -> TestResult {
    if SyscallNumber::IpcSend as u64 != 800 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(800) != Some(SyscallNumber::IpcSend) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_ipc_recv() -> TestResult {
    if SyscallNumber::IpcRecv as u64 != 801 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(801) != Some(SyscallNumber::IpcRecv) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_ipc_create() -> TestResult {
    if SyscallNumber::IpcCreate as u64 != 802 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(802) != Some(SyscallNumber::IpcCreate) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_ipc_destroy() -> TestResult {
    if SyscallNumber::IpcDestroy as u64 != 803 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(803) != Some(SyscallNumber::IpcDestroy) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_crypto_random() -> TestResult {
    if SyscallNumber::CryptoRandom as u64 != 900 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(900) != Some(SyscallNumber::CryptoRandom) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_crypto_hash() -> TestResult {
    if SyscallNumber::CryptoHash as u64 != 901 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(901) != Some(SyscallNumber::CryptoHash) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_crypto_sign() -> TestResult {
    if SyscallNumber::CryptoSign as u64 != 902 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(902) != Some(SyscallNumber::CryptoSign) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_crypto_verify() -> TestResult {
    if SyscallNumber::CryptoVerify as u64 != 903 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(903) != Some(SyscallNumber::CryptoVerify) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_crypto_encrypt() -> TestResult {
    if SyscallNumber::CryptoEncrypt as u64 != 904 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(904) != Some(SyscallNumber::CryptoEncrypt) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_crypto_decrypt() -> TestResult {
    if SyscallNumber::CryptoDecrypt as u64 != 905 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(905) != Some(SyscallNumber::CryptoDecrypt) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_crypto_keygen() -> TestResult {
    if SyscallNumber::CryptoKeyGen as u64 != 906 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(906) != Some(SyscallNumber::CryptoKeyGen) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_crypto_zk_prove() -> TestResult {
    if SyscallNumber::CryptoZkProve as u64 != 907 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(907) != Some(SyscallNumber::CryptoZkProve) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_crypto_zk_verify() -> TestResult {
    if SyscallNumber::CryptoZkVerify as u64 != 908 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(908) != Some(SyscallNumber::CryptoZkVerify) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_io_port_read() -> TestResult {
    if SyscallNumber::IoPortRead as u64 != 1000 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(1000) != Some(SyscallNumber::IoPortRead) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_io_port_write() -> TestResult {
    if SyscallNumber::IoPortWrite as u64 != 1001 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(1001) != Some(SyscallNumber::IoPortWrite) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_mmio_map() -> TestResult {
    if SyscallNumber::MmioMap as u64 != 1002 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(1002) != Some(SyscallNumber::MmioMap) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_debug_log() -> TestResult {
    if SyscallNumber::DebugLog as u64 != 1100 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(1100) != Some(SyscallNumber::DebugLog) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_admin_reboot() -> TestResult {
    if SyscallNumber::AdminReboot as u64 != 1200 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(1200) != Some(SyscallNumber::AdminReboot) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_admin_shutdown() -> TestResult {
    if SyscallNumber::AdminShutdown as u64 != 1201 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(1201) != Some(SyscallNumber::AdminShutdown) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_admin_mod_load() -> TestResult {
    if SyscallNumber::AdminModLoad as u64 != 1202 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(1202) != Some(SyscallNumber::AdminModLoad) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_admin_cap_grant() -> TestResult {
    if SyscallNumber::AdminCapGrant as u64 != 1203 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(1203) != Some(SyscallNumber::AdminCapGrant) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_admin_cap_revoke() -> TestResult {
    if SyscallNumber::AdminCapRevoke as u64 != 1204 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(1204) != Some(SyscallNumber::AdminCapRevoke) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_invalid_returns_none() -> TestResult {
    if SyscallNumber::from_u64(9999) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_max_u64_returns_none() -> TestResult {
    if SyscallNumber::from_u64(u64::MAX) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_equality() -> TestResult {
    if SyscallNumber::Read != SyscallNumber::Read {
        return TestResult::Fail;
    }
    if SyscallNumber::Read == SyscallNumber::Write {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_clone() -> TestResult {
    let num = SyscallNumber::Read;
    let cloned = num.clone();
    if num != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_copy() -> TestResult {
    let num = SyscallNumber::Write;
    let copied = num;
    if num != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_debug() -> TestResult {
    let num = SyscallNumber::Exit;
    let debug_str = format!("{:?}", num);
    if !debug_str.contains("Exit") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_epoll_create() -> TestResult {
    if SyscallNumber::EpollCreate as u64 != 213 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(213) != Some(SyscallNumber::EpollCreate) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_epoll_wait() -> TestResult {
    if SyscallNumber::EpollWait as u64 != 232 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(232) != Some(SyscallNumber::EpollWait) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_epoll_ctl() -> TestResult {
    if SyscallNumber::EpollCtl as u64 != 233 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(233) != Some(SyscallNumber::EpollCtl) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_clock_gettime() -> TestResult {
    if SyscallNumber::ClockGettime as u64 != 228 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(228) != Some(SyscallNumber::ClockGettime) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_nanosleep() -> TestResult {
    if SyscallNumber::Nanosleep as u64 != 35 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(35) != Some(SyscallNumber::Nanosleep) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_futex() -> TestResult {
    if SyscallNumber::Futex as u64 != 202 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(202) != Some(SyscallNumber::Futex) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_getrandom() -> TestResult {
    if SyscallNumber::Getrandom as u64 != 318 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(318) != Some(SyscallNumber::Getrandom) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_openat() -> TestResult {
    if SyscallNumber::Openat as u64 != 257 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(257) != Some(SyscallNumber::Openat) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_number_statx() -> TestResult {
    if SyscallNumber::Statx as u64 != 332 {
        return TestResult::Fail;
    }
    if SyscallNumber::from_u64(332) != Some(SyscallNumber::Statx) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
