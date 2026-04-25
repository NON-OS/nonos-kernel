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
use super::vk_data::VK_BOOT_AUTHORITY_BLS12_381_GROTH16;

#[cfg(all(feature = "zk-groth16", feature = "zk-vk-provisioned"))]
const _: () = { if VK_BOOT_AUTHORITY_BLS12_381_GROTH16.len() == 0 { panic!("zk-vk-provisioned set but boot authority VK empty"); } };
