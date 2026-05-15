use crate::firmware::tlv::{le32, parse_header, TLV_PAGING, TLV_SEC_INIT, TLV_SEC_RT};

#[derive(Clone, Copy)]
pub struct FirmwareStageState {
    pub major: u16,
    pub minor: u16,
    pub api: u16,
    pub build: u32,
    pub init_sections: u16,
    pub runtime_sections: u16,
    pub paging_sections: u16,
    pub staged_bytes: u32,
    pub alive_seen: bool,
    pub last_int: u32,
}

impl FirmwareStageState {
    pub const fn empty() -> Self {
        Self {
            major: 0, minor: 0, api: 0, build: 0, init_sections: 0,
            runtime_sections: 0, paging_sections: 0, staged_bytes: 0,
            alive_seen: false, last_int: 0,
        }
    }
}

pub fn stage_firmware(data: &[u8], dma_user_va: u64, dma_len: u64) -> Option<FirmwareStageState> {
    let h = parse_header(data)?;
    let mut state = FirmwareStageState {
        major: h.major, minor: h.minor, api: h.api, build: h.build,
        ..FirmwareStageState::empty()
    };
    let mut off = 20usize;
    let mut dst = 0usize;
    while off + 8 <= data.len() {
        let ty = le32(data, off)?;
        let len = le32(data, off + 4)? as usize;
        off += 8;
        if off + len > data.len() {
            return None;
        }
        if matches!(ty, TLV_SEC_RT | TLV_SEC_INIT | TLV_PAGING) && len >= 4 {
            stage_section(data, off, len, dma_user_va, dma_len as usize, &mut dst)?;
            count_section(ty, &mut state);
        }
        off += (len + 3) & !3;
    }
    state.staged_bytes = dst as u32;
    Some(state)
}

fn stage_section(data: &[u8], off: usize, len: usize, dma: u64, cap: usize, dst: &mut usize) -> Option<()> {
    let payload_len = len - 4;
    let total = 12usize.checked_add(payload_len)?;
    if dst.checked_add(total)? > cap {
        return None;
    }
    unsafe {
        let ptr = (dma as *mut u8).add(*dst);
        core::ptr::copy_nonoverlapping(data.as_ptr().add(off), ptr, 4);
        core::ptr::copy_nonoverlapping(&(payload_len as u32).to_le_bytes() as *const u8, ptr.add(4), 4);
        core::ptr::write_bytes(ptr.add(8), 0, 4);
        core::ptr::copy_nonoverlapping(data.as_ptr().add(off + 4), ptr.add(12), payload_len);
    }
    *dst += total;
    Some(())
}

fn count_section(ty: u32, state: &mut FirmwareStageState) {
    match ty {
        TLV_SEC_INIT => state.init_sections += 1,
        TLV_SEC_RT => state.runtime_sections += 1,
        TLV_PAGING => state.paging_sections += 1,
        _ => {}
    }
}
