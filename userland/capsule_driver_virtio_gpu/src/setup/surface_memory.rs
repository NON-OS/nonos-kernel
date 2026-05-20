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

use nonos_libc::{mk_dma_map, DmaMapOut};

use super::surface_trace;

const PAGE_SIZE: u64 = 4096;
const MAX_SURFACE_BYTES: u64 = 128 * 1024 * 1024;

pub struct SurfaceMemory {
    pub stride: u32,
    pub byte_len: u64,
    pub dma: DmaMapOut,
}

pub fn map_primary(
    device_id: u64,
    claim_epoch: u64,
    width: u32,
    height: u32,
) -> Result<SurfaceMemory, &'static str> {
    let stride = width.checked_mul(4).ok_or("virtio-gpu: stride overflow")?;
    let byte_len =
        (stride as u64).checked_mul(height as u64).ok_or("virtio-gpu: surface overflow")?;
    if byte_len > MAX_SURFACE_BYTES {
        return Err("virtio-gpu: surface exceeds display dma cap");
    }
    let dma_len = page_round(byte_len).ok_or("virtio-gpu: surface align overflow")?;
    surface_trace::primary(width, height, dma_len / PAGE_SIZE);
    let mut dma = DmaMapOut { user_va: 0, device_addr: 0, length: 0, grant_id: 0 };
    let rc = mk_dma_map(device_id, claim_epoch, dma_len, 0, &mut dma);
    if rc < 0 {
        return Err(dma_error(rc));
    }
    if dma.user_va == 0 || dma.device_addr == 0 || dma.length < dma_len {
        return Err("virtio-gpu: primary dma map incomplete");
    }
    Ok(SurfaceMemory { stride, byte_len, dma })
}

fn page_round(v: u64) -> Option<u64> {
    v.checked_add(PAGE_SIZE - 1).map(|x| x & !(PAGE_SIZE - 1))
}

fn dma_error(rc: i64) -> &'static str {
    match rc {
        -1 => "virtio-gpu: primary dma denied",
        -12 => "virtio-gpu: primary dma no memory",
        -19 => "virtio-gpu: primary dma no device",
        -22 => "virtio-gpu: primary dma invalid length",
        -95 => "virtio-gpu: primary dma flags unsupported",
        -116 => "virtio-gpu: primary dma stale claim",
        _ => "virtio-gpu: primary dma map failed",
    }
}
