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

use crate::syscall::SyscallNumber;

// Display name for an audit log entry. Kept in lockstep with the
// `SyscallNumber` enum; the compiler enforces exhaustive coverage.
pub(super) fn syscall_name(syscall: SyscallNumber) -> &'static str {
    match syscall {
        SyscallNumber::CryptoRandom => "CryptoRandom",
        SyscallNumber::CryptoHash => "CryptoHash",
        SyscallNumber::CryptoSign => "CryptoSign",
        SyscallNumber::CryptoVerify => "CryptoVerify",
        SyscallNumber::CryptoEncrypt => "CryptoEncrypt",
        SyscallNumber::CryptoDecrypt => "CryptoDecrypt",
        SyscallNumber::CryptoKeyGen => "CryptoKeyGen",
        SyscallNumber::CryptoZkProve => "CryptoZkProve",
        SyscallNumber::CryptoZkVerify => "CryptoZkVerify",
        SyscallNumber::CryptoEd25519Verify => "CryptoEd25519Verify",
        SyscallNumber::DebugLog => "DebugLog",
        SyscallNumber::DebugTrace => "DebugTrace",
        SyscallNumber::AdminReboot => "AdminReboot",
        SyscallNumber::AdminShutdown => "AdminShutdown",
        SyscallNumber::AdminModLoad => "AdminModLoad",
        SyscallNumber::GraphicsDisplayDimensions => "GraphicsDisplayDimensions",
        SyscallNumber::GraphicsSurfaceCreate => "GraphicsSurfaceCreate",
        SyscallNumber::GraphicsSurfaceDestroy => "GraphicsSurfaceDestroy",
        SyscallNumber::GraphicsSurfaceMap => "GraphicsSurfaceMap",
        SyscallNumber::GraphicsSurfacePresentFull => "GraphicsSurfacePresentFull",
        SyscallNumber::GraphicsSurfacePresentRect => "GraphicsSurfacePresentRect",
        SyscallNumber::GraphicsDisplayList => "GraphicsDisplayList",
        SyscallNumber::GraphicsCursorPresent => "GraphicsCursorPresent",
        SyscallNumber::MkIpcSend => "MkIpcSend",
        SyscallNumber::MkIpcRecv => "MkIpcRecv",
        SyscallNumber::MkIpcCall => "MkIpcCall",
        SyscallNumber::MkIpcRecvFrom => "MkIpcRecvFrom",
        SyscallNumber::MkIpcSendToPid => "MkIpcSendToPid",
        SyscallNumber::MkServiceLookup => "MkServiceLookup",
        SyscallNumber::MkMmap => "MkMmap",
        SyscallNumber::MkMunmap => "MkMunmap",
        SyscallNumber::MkSpawn => "MkSpawn",
        SyscallNumber::MkExit => "MkExit",
        SyscallNumber::MkYield => "MkYield",
        SyscallNumber::MkCapGrant => "MkCapGrant",
        SyscallNumber::MkCapRevoke => "MkCapRevoke",
        SyscallNumber::MkCapCheck => "MkCapCheck",
        SyscallNumber::MkDeviceList => "MkDeviceList",
        SyscallNumber::MkDeviceClaim => "MkDeviceClaim",
        SyscallNumber::MkDeviceRelease => "MkDeviceRelease",
        SyscallNumber::MkMmioMap => "MkMmioMap",
        SyscallNumber::MkMmioUnmap => "MkMmioUnmap",
        SyscallNumber::MkIrqBind => "MkIrqBind",
        SyscallNumber::MkIrqUnbind => "MkIrqUnbind",
        SyscallNumber::MkIrqAck => "MkIrqAck",
        SyscallNumber::MkIrqPoll => "MkIrqPoll",
        SyscallNumber::MkDmaMap => "MkDmaMap",
        SyscallNumber::MkDmaUnmap => "MkDmaUnmap",
        SyscallNumber::MkPioGrant => "MkPioGrant",
        SyscallNumber::MkPioRead => "MkPioRead",
        SyscallNumber::MkPioWrite => "MkPioWrite",
        SyscallNumber::MkPioRelease => "MkPioRelease",
        SyscallNumber::MkDebug => "MkDebug",
    }
}
