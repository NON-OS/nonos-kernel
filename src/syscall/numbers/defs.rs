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

// Active NØNOS syscall ABI. Discriminants are 4-byte ASCII tags
// packed little-endian via `tag4`; the registry in
// `crate::syscall::abi::REGISTRY` is the source of truth.

use crate::syscall::abi::tag4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum SyscallNumber {
    CryptoRandom = tag4(b"CRND"),
    CryptoHash = tag4(b"CHSH"),
    CryptoSign = tag4(b"CSGN"),
    CryptoVerify = tag4(b"CVRF"),
    CryptoEncrypt = tag4(b"CENC"),
    CryptoDecrypt = tag4(b"CDEC"),
    CryptoKeyGen = tag4(b"CKGN"),
    CryptoZkProve = tag4(b"CZKP"),
    CryptoZkVerify = tag4(b"CZKV"),
    CryptoEd25519Verify = tag4(b"CEDV"),

    IoPortRead = tag4(b"HPRD"),
    IoPortWrite = tag4(b"HPWR"),
    MmioMap = tag4(b"HMMP"),

    DebugLog = tag4(b"DLOG"),
    DebugTrace = tag4(b"DTRC"),

    AdminReboot = tag4(b"ARBT"),
    AdminShutdown = tag4(b"ASDN"),
    AdminModLoad = tag4(b"AMOD"),
    AdminCapGrant = tag4(b"ACGT"),
    AdminCapRevoke = tag4(b"ACRV"),

    GraphicsDisplayDimensions = tag4(b"GDIM"),
    GraphicsSurfaceCreate = tag4(b"GSCR"),
    GraphicsSurfaceDestroy = tag4(b"GSDS"),
    GraphicsSurfaceMap = tag4(b"GSMP"),
    GraphicsSurfacePresentFull = tag4(b"GPRF"),
    GraphicsSurfacePresentRect = tag4(b"GPRR"),
    GraphicsDisplayList = tag4(b"GDLS"),
    GraphicsCursorPresent = tag4(b"GCUR"),

    MkIpcSend = tag4(b"MISD"),
    MkIpcRecv = tag4(b"MIRC"),
    MkIpcCall = tag4(b"MICL"),
    MkMmap = tag4(b"MMAP"),
    MkMunmap = tag4(b"MUMP"),
    MkSpawn = tag4(b"MSPN"),
    MkExit = tag4(b"MEXT"),
    MkYield = tag4(b"MYLD"),
    MkCapGrant = tag4(b"MCGT"),
    MkCapRevoke = tag4(b"MCRV"),
    MkCapCheck = tag4(b"MCCK"),
    MkDeviceList = tag4(b"MDLS"),
    MkDeviceClaim = tag4(b"MDCL"),
    MkDeviceRelease = tag4(b"MDRL"),
    MkMmioMap = tag4(b"MMMP"),
    MkMmioUnmap = tag4(b"MMUM"),
    MkIrqBind = tag4(b"MIRB"),
    MkIrqUnbind = tag4(b"MIRU"),
    MkIrqAck = tag4(b"MIRA"),
    MkIrqPoll = tag4(b"MIRP"),
    MkDmaMap = tag4(b"MDMM"),
    MkDmaUnmap = tag4(b"MDMU"),
    MkPioGrant = tag4(b"MPGT"),
    MkPioRead = tag4(b"MPRD"),
    MkPioWrite = tag4(b"MPWR"),
    MkPioRelease = tag4(b"MPRL"),
    MkDebug = tag4(b"MDBG"),
}
