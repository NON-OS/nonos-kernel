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

use super::nvme_error::NvmeError;

impl From<&'static str> for NvmeError {
    fn from(s: &'static str) -> Self {
        match s {
            "No NVMe controller found" => Self::NoControllerFound,
            "NVMe BAR0 is not MMIO" => Self::Bar0NotMmio,
            "NVMe: timeout waiting for CC.EN=0 -> CSTS.RDY=0" => Self::ControllerDisableTimeout,
            "NVMe: timeout waiting for CSTS.RDY=1" => Self::ControllerEnableTimeout,
            "NVMe: namespace not ready" => Self::NamespaceNotReady,
            "NVMe: LBA range overflow" => Self::LbaRangeOverflow,
            "NVMe: LBA range exceeds namespace capacity" => Self::LbaExceedsCapacity,
            "NVMe: invalid block count (zero)" => Self::InvalidBlockCount,
            "NVMe: DMA buffer too large" => Self::DmaBufferTooLarge,
            "NVMe: DMA buffer size is zero" => Self::DmaBufferSizeZero,
            "NVMe: DMA buffer overlaps kernel memory" => Self::DmaBufferOverlapsKernel,
            "NVMe: Rate limit exceeded" => Self::RateLimitExceeded,
            "NVMe: IO queue not ready" => Self::IoQueueNotReady,
            "NVMe: CQ poll timeout" => Self::CommandTimeout,
            "NVMe: CQ corruption detected (too many CID mismatches)" => Self::CqCorruption,
            "NVMe: Command failed (SC != 0)" => Self::CommandFailed { status_code: 0 },
            "NVMe not initialized" => Self::ControllerNotInitialized,
            _ => Self::CommandFailed { status_code: 0xFFFF },
        }
    }
}
