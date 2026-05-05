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

/// Per-capsule policy values that the shared spawn pipeline reads.
/// Everything else — CR3 dance, kernel/user stack, iretq frame,
/// endpoint registration, run-queue insert — is kernel primitive and
/// lives in `runner`.
pub struct CapsuleSpec {
    pub name: &'static str,
    pub service_port: u32,
    pub reply_inbox: &'static str,
    pub reply_port: u32,
    pub elf: &'static [u8],
    pub caps_bits: u64,
    pub debug_tag: &'static [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    FeatureDisabled,
    ElfLoad,
    ProcessCreation,
    AddressSpace,
    EndpointCollision,
}
