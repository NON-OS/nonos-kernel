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

use nonos_libc::{
    mk_dma_map, mk_dma_unmap, mk_surface_register, mk_surface_share, DmaMapOut, SurfaceDescriptor,
    SURFACE_FORMAT_ARGB8888,
};

use crate::constants::VG_FORMAT_B8G8R8A8_UNORM;
use crate::device::cmd;
use crate::device::cmd::transfer_to_host_2d::Rect;
use crate::device::virtqueue::ControlQueue;
use crate::state::{FenceCounter, Resource, ResourceTable, Scanout};

const PAGE_SIZE: u64 = 4096;
const PAGE_MASK: u64 = PAGE_SIZE - 1;

#[derive(Clone, Copy)]
pub struct Primary {
    pub handle: u64,
    pub resource_id: u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
}

pub fn create(
    device_id: u64,
    claim_epoch: u64,
    q: &ControlQueue,
    fences: &FenceCounter,
    resources: &ResourceTable,
    scanout: Scanout,
) -> Result<Option<Primary>, &'static str> {
    if !scanout.enabled || scanout.width == 0 || scanout.height == 0 {
        return Ok(None);
    }
    let stride = scanout.width.checked_mul(4).ok_or("virtio-gpu: stride overflow")?;
    let byte_len =
        (stride as u64).checked_mul(scanout.height as u64).ok_or("virtio-gpu: surface overflow")?;
    if byte_len > u32::MAX as u64 {
        return Err("virtio-gpu: surface too large");
    }
    let map_len =
        byte_len.checked_add(PAGE_MASK).ok_or("virtio-gpu: surface map length overflow")?
            & !PAGE_MASK;
    let mut dma = DmaMapOut { user_va: 0, device_addr: 0, length: 0, grant_id: 0 };
    let rc = mk_dma_map(device_id, claim_epoch, map_len, 0, &mut dma);
    if rc < 0 || dma.user_va == 0 || dma.device_addr == 0 {
        return Err("virtio-gpu: primary dma map failed");
    }
    let resource_id = resources.alloc_id();
    cmd::create_resource_2d(
        q,
        fences.issue(),
        resource_id,
        VG_FORMAT_B8G8R8A8_UNORM,
        scanout.width,
        scanout.height,
    )?;
    cmd::attach_backing(q, fences.issue(), resource_id, dma.device_addr, byte_len as u32)?;
    cmd::set_scanout(
        q,
        fences.issue(),
        0,
        resource_id,
        Rect { x: 0, y: 0, width: scanout.width, height: scanout.height },
    )?;
    let desc = SurfaceDescriptor {
        width: scanout.width,
        height: scanout.height,
        stride,
        format: SURFACE_FORMAT_ARGB8888,
        byte_len,
        base_va: dma.user_va,
        flags: 0,
    };
    let sid = mk_surface_register(&desc);
    if sid < 0 {
        let _ = mk_dma_unmap(dma.grant_id);
        return Err("virtio-gpu: surface register rejected");
    }
    let handle = mk_surface_share(sid as u64);
    if handle < 0 {
        let _ = mk_dma_unmap(dma.grant_id);
        return Err("virtio-gpu: surface share rejected");
    }
    if resources
        .insert(Resource {
            resource_id,
            owner_pid: 0,
            width: scanout.width,
            height: scanout.height,
            format: VG_FORMAT_B8G8R8A8_UNORM,
            backing_addr: dma.device_addr,
            backing_len: byte_len as u32,
            in_use: true,
        })
        .is_err()
    {
        let _ = mk_dma_unmap(dma.grant_id);
        return Err("virtio-gpu: resource table full");
    }
    Ok(Some(Primary {
        handle: handle as u64,
        resource_id,
        width: scanout.width,
        height: scanout.height,
        stride,
    }))
}
