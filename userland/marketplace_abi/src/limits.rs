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

//! Bounded sizes the codec enforces. A marketplace index that
//! exceeds any of these is rejected before the decoder allocates
//! anything; a hostile or corrupted index cannot inflate userland
//! memory beyond `MAX_INDEX_BLOB`.

pub const PUBKEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;
pub const SHA256_LEN: usize = 32;

pub const MAX_ENTRIES: u32 = 1024;
pub const MAX_RELEASES: u32 = 64;
pub const MAX_ARCHES: u32 = 8;
pub const MAX_CAPABILITIES: u32 = 64;

pub const MAX_NAME: u32 = 128;
pub const MAX_PUBLISHER: u32 = 128;
pub const MAX_DESCRIPTION: u32 = 4096;
pub const MAX_URL: u32 = 1024;
pub const MAX_SUPPORTED_ARCH_LEN: u32 = 32;
pub const MAX_TOKEN_SYMBOL: u32 = 16;
pub const MAX_SIGNATURE: u32 = 256; // canonical Ed25519 is 64; cushion for future schemes

/// Hard cap on a single index blob. Two MiB covers ~1k entries with
/// generous metadata and is well within the userland heap budget.
pub const MAX_INDEX_BLOB: usize = 2 * 1024 * 1024;
