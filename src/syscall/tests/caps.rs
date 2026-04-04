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

use crate::capabilities::{Capability, CapabilityToken};

#[test]
fn test_capability_token_can_exit_requires_core_exec() {
    let token = CapabilityToken::with_caps(&[Capability::CoreExec]);
    assert!(token.can_exit());
}

#[test]
fn test_capability_token_can_exit_without_core_exec() {
    let token = CapabilityToken::with_caps(&[Capability::IO]);
    assert!(!token.can_exit());
}

#[test]
fn test_capability_token_can_getpid() {
    let token = CapabilityToken::with_caps(&[Capability::CoreExec]);
    assert!(token.can_getpid());
}

#[test]
fn test_capability_token_can_fork() {
    let token = CapabilityToken::with_caps(&[Capability::CoreExec]);
    assert!(token.can_fork());
}

#[test]
fn test_capability_token_can_exec() {
    let token = CapabilityToken::with_caps(&[Capability::CoreExec]);
    assert!(token.can_exec());
}

#[test]
fn test_capability_token_can_wait() {
    let token = CapabilityToken::with_caps(&[Capability::CoreExec]);
    assert!(token.can_wait());
}

#[test]
fn test_capability_token_can_signal() {
    let token = CapabilityToken::with_caps(&[Capability::CoreExec]);
    assert!(token.can_signal());
}

#[test]
fn test_capability_token_can_read() {
    let token = CapabilityToken::with_caps(&[Capability::IO]);
    assert!(token.can_read());
}

#[test]
fn test_capability_token_can_read_without_io() {
    let token = CapabilityToken::with_caps(&[Capability::CoreExec]);
    assert!(!token.can_read());
}

#[test]
fn test_capability_token_can_write() {
    let token = CapabilityToken::with_caps(&[Capability::IO]);
    assert!(token.can_write());
}

#[test]
fn test_capability_token_can_open_files() {
    let token = CapabilityToken::with_caps(&[Capability::FileSystem]);
    assert!(token.can_open_files());
}

#[test]
fn test_capability_token_can_close_files() {
    let token = CapabilityToken::with_caps(&[Capability::FileSystem]);
    assert!(token.can_close_files());
}

#[test]
fn test_capability_token_can_stat() {
    let token = CapabilityToken::with_caps(&[Capability::FileSystem]);
    assert!(token.can_stat());
}

#[test]
fn test_capability_token_can_seek() {
    let token = CapabilityToken::with_caps(&[Capability::FileSystem]);
    assert!(token.can_seek());
}

#[test]
fn test_capability_token_can_modify_dirs() {
    let token = CapabilityToken::with_caps(&[Capability::FileSystem]);
    assert!(token.can_modify_dirs());
}

#[test]
fn test_capability_token_can_unlink() {
    let token = CapabilityToken::with_caps(&[Capability::FileSystem]);
    assert!(token.can_unlink());
}

#[test]
fn test_capability_token_can_allocate_memory() {
    let token = CapabilityToken::with_caps(&[Capability::Memory]);
    assert!(token.can_allocate_memory());
}

#[test]
fn test_capability_token_can_deallocate_memory() {
    let token = CapabilityToken::with_caps(&[Capability::Memory]);
    assert!(token.can_deallocate_memory());
}

#[test]
fn test_capability_token_can_network() {
    let token = CapabilityToken::with_caps(&[Capability::Network]);
    assert!(token.can_network());
}

#[test]
fn test_capability_token_can_ipc() {
    let token = CapabilityToken::with_caps(&[Capability::IPC]);
    assert!(token.can_ipc());
}

#[test]
fn test_capability_token_can_crypto() {
    let token = CapabilityToken::with_caps(&[Capability::Crypto]);
    assert!(token.can_crypto());
}

#[test]
fn test_capability_token_can_hardware() {
    let token = CapabilityToken::with_caps(&[Capability::Hardware]);
    assert!(token.can_hardware());
}

#[test]
fn test_capability_token_can_debug() {
    let token = CapabilityToken::with_caps(&[Capability::Debug]);
    assert!(token.can_debug());
}

#[test]
fn test_capability_token_can_admin() {
    let token = CapabilityToken::with_caps(&[Capability::Admin]);
    assert!(token.can_admin());
}

#[test]
fn test_capability_token_empty_cannot_do_anything() {
    let token = CapabilityToken::empty();
    assert!(!token.can_exit());
    assert!(!token.can_read());
    assert!(!token.can_write());
    assert!(!token.can_network());
    assert!(!token.can_crypto());
    assert!(!token.can_admin());
}

#[test]
fn test_capability_token_multiple_capabilities() {
    let token = CapabilityToken::with_caps(&[Capability::CoreExec, Capability::IO, Capability::Network]);
    assert!(token.can_exit());
    assert!(token.can_read());
    assert!(token.can_write());
    assert!(token.can_network());
    assert!(!token.can_crypto());
    assert!(!token.can_admin());
}

#[test]
fn test_capability_token_all_capabilities() {
    let token = CapabilityToken::with_caps(&Capability::all());
    assert!(token.can_exit());
    assert!(token.can_read());
    assert!(token.can_write());
    assert!(token.can_network());
    assert!(token.can_crypto());
    assert!(token.can_admin());
    assert!(token.can_hardware());
    assert!(token.can_debug());
    assert!(token.can_ipc());
    assert!(token.can_allocate_memory());
    assert!(token.can_open_files());
}
