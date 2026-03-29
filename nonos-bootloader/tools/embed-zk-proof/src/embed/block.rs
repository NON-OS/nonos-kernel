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

pub const ZK_PROOF_MAGIC: [u8; 4] = [0x4E, 0xC3, 0x5A, 0x50];
pub const ZK_PROOF_VERSION: u32 = 2;
pub const ZK_HEADER_SIZE: usize = 176;

pub struct ZkBlockParams<'a> {
    pub program_hash: &'a [u8; 32],
    pub capsule_commitment: &'a [u8; 32],
    pub kernel_hash: &'a [u8; 32],
    pub boot_nonce: &'a [u8; 32],
    pub machine_id: &'a [u8; 32],
    pub public_inputs: &'a [u8],
    pub proof_blob: &'a [u8],
}

pub fn create_zk_block(params: &ZkBlockParams) -> Vec<u8> {
    let total_size = ZK_HEADER_SIZE + params.public_inputs.len() + params.proof_blob.len();
    let mut block = Vec::with_capacity(total_size);

    block.extend_from_slice(&ZK_PROOF_MAGIC);
    block.extend_from_slice(&ZK_PROOF_VERSION.to_le_bytes());
    block.extend_from_slice(params.program_hash);
    block.extend_from_slice(params.capsule_commitment);
    block.extend_from_slice(params.kernel_hash);
    block.extend_from_slice(params.boot_nonce);
    block.extend_from_slice(params.machine_id);
    block.extend_from_slice(&(params.public_inputs.len() as u32).to_le_bytes());
    block.extend_from_slice(&(params.proof_blob.len() as u32).to_le_bytes());
    block.extend_from_slice(params.public_inputs);
    block.extend_from_slice(params.proof_blob);

    block
}
