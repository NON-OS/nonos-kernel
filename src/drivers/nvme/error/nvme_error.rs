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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeError {
    NoControllerFound,
    Bar0NotMmio,
    ControllerDisableTimeout,
    ControllerEnableTimeout,
    ControllerFatalStatus,
    AdminQueueCreationFailed,
    IoQueueCreationFailed,
    IdentifyControllerFailed,
    IdentifyNamespaceFailed,
    NoActiveNamespaces,
    NamespaceNotReady,
    InvalidNamespaceId,
    LbaRangeOverflow,
    LbaExceedsCapacity,
    InvalidBlockCount,
    DmaAllocationFailed,
    DmaBufferTooLarge,
    DmaBufferSizeZero,
    DmaBufferOverlapsKernel,
    DmaBufferAddressOverflow,
    PrpListAllocationFailed,
    CommandTimeout,
    CommandFailed { status_code: u16 },
    CqCorruption,
    CidMismatch,
    PhaseTagError,
    RateLimitExceeded,
    IoQueueNotReady,
    QueueFull,
    InvalidPrpAlignment,
    MsixConfigurationFailed,
    InterruptAllocationFailed,
    InterruptTimeout,
    ControllerNotInitialized,
    SubmissionQueueError,
    CompletionQueueError,
    InvalidQueueSize,
    UnsupportedPageSize,
    CapabilityReadError,
    DoorbellStrideError,
}
