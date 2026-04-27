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

use crate::syscall::dispatch::crypto::*;
use crate::syscall::dispatch::process::{
    handle_ipc_create, handle_ipc_destroy, handle_ipc_recv, handle_ipc_send,
};
use crate::syscall::dispatch::util::errno;
use crate::syscall::numbers::SyscallNumber;
use crate::syscall::SyscallResult;

pub(super) fn dispatch_ipc_crypto(
    syscall: SyscallNumber,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> SyscallResult {
    match syscall {
        SyscallNumber::IpcSend => handle_ipc_send(a0, a1, a2),
        SyscallNumber::IpcRecv => handle_ipc_recv(a0, a1, a2),
        SyscallNumber::IpcCreate => handle_ipc_create(a0),
        SyscallNumber::IpcDestroy => handle_ipc_destroy(a0),
        SyscallNumber::CryptoRandom => handle_crypto_random(a0, a1),
        SyscallNumber::Getrandom => crate::syscall::extended::handle_getrandom(a0, a1, a2 as u32),
        SyscallNumber::CryptoHash => handle_crypto_hash(a0, a1, a2),
        SyscallNumber::CryptoSign => handle_crypto_sign(a0, a1, a2, a3),
        SyscallNumber::CryptoVerify => handle_crypto_verify(a0, a1, a2, a3),
        SyscallNumber::CryptoEncrypt => handle_crypto_encrypt(a0, a1, a2, a3, a4, a5),
        SyscallNumber::CryptoDecrypt => handle_crypto_decrypt(a0, a1, a2, a3, a4, a5),
        SyscallNumber::CryptoKeyGen => handle_crypto_keygen(a0, a1, a2),
        SyscallNumber::CryptoZkProve => handle_crypto_zk_prove(a0, a1, a2, a3),
        SyscallNumber::CryptoZkVerify => handle_crypto_zk_verify(a0, a1, a2, a3),
        _ => errno(38),
    }
}
