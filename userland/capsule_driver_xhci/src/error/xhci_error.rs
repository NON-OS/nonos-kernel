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

//! P0 controller-bring-up error surface. Each variant maps to a
//! deterministic errno value through `errno_value()`; that
//! mapping is what the kernel-side spawn renders on capsule
//! exit. P1 will grow the surface (port-reset failures, slot
//! exhaustion, address-device errors, transfer faults).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhciError {
    /// `MkDeviceList` returned no xHCI controller (class 0x0071).
    DeviceNotFound,
    /// Broker syscall failed; the inner i64 is the broker's negative
    /// errno return.
    BrokerCallFailed(i64),
    /// Controller advertises a feature this slice cannot drive
    /// (e.g. 32-bit-only addressing, zero device slots).
    ControllerUnsupported,
    /// HCRST never self-cleared inside the spin bound.
    ResetTimeout,
    /// USBSTS.CNR stayed set after HCRST cleared.
    ControllerNotReadyTimeout,
    /// USBSTS.HCH stayed set after USBCMD.RS=1.
    StartTimeout,
    /// USBSTS.HCH stayed clear after USBCMD.RS=0 in halt phase.
    HaltTimeout,
    /// Command-ring wrap caught the consumer; ring is full and the
    /// capsule has nowhere to enqueue.
    CommandRingFull,
    /// Spin bound elapsed without seeing the matching Command
    /// Completion Event for the issued command.
    CommandCompletionTimeout,
    /// Command Completion Event arrived but the completion-code
    /// byte was not `CC_SUCCESS`. Inner u8 is the raw completion
    /// code so the kernel-side smoke can render it.
    CommandCompletionFailed(u8),
}
