// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Capability token syscall permission tests

use crate::capabilities::{Capability, CapabilityToken};
use crate::test::framework::TestResult;

pub(crate) fn test_capability_token_can_exit_requires_core_exec() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::CoreExec]);
    if !token.can_exit() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_exit_without_core_exec() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::IO]);
    if token.can_exit() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_getpid() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::CoreExec]);
    if !token.can_getpid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_fork() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::CoreExec]);
    if !token.can_fork() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_exec() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::CoreExec]);
    if !token.can_exec() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_wait() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::CoreExec]);
    if !token.can_wait() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_signal() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::CoreExec]);
    if !token.can_signal() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_read() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::IO]);
    if !token.can_read() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_read_without_io() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::CoreExec]);
    if token.can_read() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_write() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::IO]);
    if !token.can_write() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_open_files() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::FileSystem]);
    if !token.can_open_files() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_close_files() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::FileSystem]);
    if !token.can_close_files() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_stat() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::FileSystem]);
    if !token.can_stat() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_seek() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::FileSystem]);
    if !token.can_seek() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_modify_dirs() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::FileSystem]);
    if !token.can_modify_dirs() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_unlink() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::FileSystem]);
    if !token.can_unlink() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_allocate_memory() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::Memory]);
    if !token.can_allocate_memory() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_deallocate_memory() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::Memory]);
    if !token.can_deallocate_memory() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_network() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::Network]);
    if !token.can_network() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_ipc() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::IPC]);
    if !token.can_ipc() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_crypto() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::Crypto]);
    if !token.can_crypto() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_hardware() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::Hardware]);
    if !token.can_hardware() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_debug() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::Debug]);
    if !token.can_debug() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_admin() -> TestResult {
    let token = CapabilityToken::with_caps(&[Capability::Admin]);
    if !token.can_admin() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_empty_cannot_do_anything() -> TestResult {
    let token = CapabilityToken::empty();
    if token.can_exit() {
        return TestResult::Fail;
    }
    if token.can_read() {
        return TestResult::Fail;
    }
    if token.can_write() {
        return TestResult::Fail;
    }
    if token.can_network() {
        return TestResult::Fail;
    }
    if token.can_crypto() {
        return TestResult::Fail;
    }
    if token.can_admin() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_multiple_capabilities() -> TestResult {
    let token =
        CapabilityToken::with_caps(&[Capability::CoreExec, Capability::IO, Capability::Network]);
    if !token.can_exit() {
        return TestResult::Fail;
    }
    if !token.can_read() {
        return TestResult::Fail;
    }
    if !token.can_write() {
        return TestResult::Fail;
    }
    if !token.can_network() {
        return TestResult::Fail;
    }
    if token.can_crypto() {
        return TestResult::Fail;
    }
    if token.can_admin() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_all_capabilities() -> TestResult {
    let token = CapabilityToken::with_caps(&Capability::all());
    if !token.can_exit() {
        return TestResult::Fail;
    }
    if !token.can_read() {
        return TestResult::Fail;
    }
    if !token.can_write() {
        return TestResult::Fail;
    }
    if !token.can_network() {
        return TestResult::Fail;
    }
    if !token.can_crypto() {
        return TestResult::Fail;
    }
    if !token.can_admin() {
        return TestResult::Fail;
    }
    if !token.can_hardware() {
        return TestResult::Fail;
    }
    if !token.can_debug() {
        return TestResult::Fail;
    }
    if !token.can_ipc() {
        return TestResult::Fail;
    }
    if !token.can_allocate_memory() {
        return TestResult::Fail;
    }
    if !token.can_open_files() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
