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

use super::commands::SubmissionEntry;

impl SubmissionEntry {
    pub fn build_identify(cid: u16, nsid: u32, cns: u32, prp1: u64) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::super::constants::ADMIN_OPC_IDENTIFY);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.cdw10 = cns;
        cmd
    }

    pub fn build_create_cq(
        cid: u16,
        qid: u16,
        qsize: u16,
        prp: u64,
        irq_vector: u16,
        irq_enabled: bool,
    ) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::super::constants::ADMIN_OPC_CREATE_CQ);
        cmd.set_cid(cid);
        cmd.prp1 = prp;
        cmd.cdw10 = ((qsize.saturating_sub(1) as u32) << 16) | (qid as u32);
        let mut cdw11 = super::super::constants::CQ_FLAGS_PHYS_CONTIG as u32;
        if irq_enabled {
            cdw11 |= super::super::constants::CQ_FLAGS_IRQ_ENABLED as u32;
        }
        cdw11 |= (irq_vector as u32) << 16;
        cmd.cdw11 = cdw11;
        cmd
    }

    pub fn build_create_sq(
        cid: u16,
        qid: u16,
        qsize: u16,
        prp: u64,
        cqid: u16,
        priority: u8,
    ) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::super::constants::ADMIN_OPC_CREATE_SQ);
        cmd.set_cid(cid);
        cmd.prp1 = prp;
        cmd.cdw10 = ((qsize.saturating_sub(1) as u32) << 16) | (qid as u32);
        let mut cdw11 = super::super::constants::SQ_FLAGS_PHYS_CONTIG as u32;
        cdw11 |= ((priority & 0x3) as u32) << 1;
        cdw11 |= (cqid as u32) << 16;
        cmd.cdw11 = cdw11;
        cmd
    }

    pub fn build_read(
        cid: u16,
        nsid: u32,
        lba: u64,
        block_count: u16,
        prp1: u64,
        prp2: u64,
    ) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::super::constants::IO_OPC_READ);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.prp2 = prp2;
        cmd.cdw10 = (lba & 0xFFFF_FFFF) as u32;
        cmd.cdw11 = ((lba >> 32) & 0xFFFF_FFFF) as u32;
        cmd.cdw12 = (block_count.saturating_sub(1) as u32) & 0xFFFF;
        cmd
    }

    pub fn build_write(
        cid: u16,
        nsid: u32,
        lba: u64,
        block_count: u16,
        prp1: u64,
        prp2: u64,
    ) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::super::constants::IO_OPC_WRITE);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.prp2 = prp2;
        cmd.cdw10 = (lba & 0xFFFF_FFFF) as u32;
        cmd.cdw11 = ((lba >> 32) & 0xFFFF_FFFF) as u32;
        cmd.cdw12 = (block_count.saturating_sub(1) as u32) & 0xFFFF;
        cmd
    }

    pub fn build_flush(cid: u16, nsid: u32) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::super::constants::IO_OPC_FLUSH);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd
    }

    pub fn build_dsm(
        cid: u16,
        nsid: u32,
        range_count: u8,
        attributes: u32,
        prp1: u64,
    ) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::super::constants::IO_OPC_DSM);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.cdw10 = range_count.saturating_sub(1) as u32;
        cmd.cdw11 = attributes;
        cmd
    }

    pub fn build_get_features(cid: u16, fid: u8, nsid: u32) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::super::constants::ADMIN_OPC_GET_FEATURES);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd.cdw10 = fid as u32;
        cmd
    }

    pub fn build_set_features(cid: u16, fid: u8, nsid: u32, value: u32) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::super::constants::ADMIN_OPC_SET_FEATURES);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd.cdw10 = fid as u32;
        cmd.cdw11 = value;
        cmd
    }

    pub fn build_abort(cid: u16, sqid: u16, abort_cid: u16) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::super::constants::ADMIN_OPC_ABORT);
        cmd.set_cid(cid);
        cmd.cdw10 = (sqid as u32) | ((abort_cid as u32) << 16);
        cmd
    }

    pub fn build_get_log_page(
        cid: u16,
        nsid: u32,
        lid: u8,
        numdl: u16,
        prp1: u64,
    ) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::super::constants::ADMIN_OPC_GET_LOG_PAGE);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.cdw10 = (lid as u32) | (((numdl as u32) & 0xFFFF) << 16);
        cmd
    }
}
