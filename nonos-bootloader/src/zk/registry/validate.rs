// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

#[cfg(feature = "zk-groth16")]
use super::program_hash::{
    VK_ALL_BYTES, ZK_BUILD_TIMESTAMP, ZK_FROM_CEREMONY, ZK_REGISTRY_VERSION,
};

#[cfg(all(feature = "zk-groth16", feature = "zk-vk-provisioned"))]
const _: [(); 1] = [(); (VK_ALL_BYTES.len() >= 96) as usize];

#[cfg(feature = "zk-groth16")]
pub fn validate_registry_metadata() -> bool {
    ZK_REGISTRY_VERSION >= 1 && (ZK_FROM_CEREMONY || ZK_BUILD_TIMESTAMP > 0)
}

#[cfg(feature = "zk-groth16")]
pub fn get_registry_info() -> (u32, u64, bool) {
    (ZK_REGISTRY_VERSION, ZK_BUILD_TIMESTAMP, ZK_FROM_CEREMONY)
}
