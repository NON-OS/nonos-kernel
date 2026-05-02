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

/// Policy bucket the contract has classified the trap into.
///
/// `UserFault` and `KernelFault` carry the same `FaultKind` set because
/// the architectural cause shape is identical; the wrapping variant is
/// what selects the policy. `Fatal` is reserved for trap classes that
/// are non-recoverable by construction (double fault, machine check,
/// NMI), independent of the privilege level the trap was taken from.
#[derive(Debug, Clone, Copy)]
pub enum TrapClass {
    UserFault(FaultKind),
    KernelFault(FaultKind),
    Fatal,
}

#[derive(Debug, Clone, Copy)]
pub enum FaultKind {
    Page,
    Protection,
    InvalidOpcode,
    Alignment,
    Arithmetic,
    Other,
}
