mod discover;

use nonos_libc::{
    mk_mmap, mk_surface_register, mk_surface_release, mk_surface_share, nonos_display_dimensions,
    SurfaceDescriptor, SURFACE_FORMAT_ARGB8888,
};

use crate::clients::compositor;
use crate::render;
use crate::state::Context;

const PROT_READ_WRITE: i32 = 0x3;
const MAP_PRIVATE_ANON: i32 = 0x22;
const OVERLAY_Z: u32 = 1;

pub fn run() -> Result<Context, &'static str> {
    let keyring_port = discover::lookup_keyring_port()?;
    let desktop_shell_port = discover::lookup_desktop_shell_port()?;
    let compositor_port = discover::lookup_compositor_port()?;
    compositor::healthcheck(compositor_port, 1).map_err(|_| "compositor health failed")?;
    let mut width: u32 = 0;
    let mut height: u32 = 0;
    let rc = nonos_display_dimensions(0, &mut width as *mut u32, &mut height as *mut u32);
    if rc != 0 || width == 0 || height == 0 {
        return Err("display dimensions unavailable");
    }
    let stride = width.checked_mul(4).ok_or("stride overflow")?;
    let byte_len = (stride as u64).checked_mul(height as u64).ok_or("surface size overflow")?;
    let base =
        mk_mmap(core::ptr::null_mut(), byte_len as usize, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0);
    if base.is_null() {
        return Err("backing mmap failed");
    }
    let backing_va = base as u64;
    let ctx = Context::new(
        keyring_port,
        desktop_shell_port,
        compositor_port,
        width,
        height,
        stride,
        backing_va,
    );
    render::paint_locked(&ctx);
    let desc = SurfaceDescriptor {
        width,
        height,
        stride,
        format: SURFACE_FORMAT_ARGB8888,
        byte_len,
        base_va: backing_va,
        flags: 0,
    };
    let sid = mk_surface_register(&desc);
    if sid < 0 {
        return Err("surface register rejected");
    }
    let handle = mk_surface_share(sid as u64);
    if handle <= 0 {
        return Err("surface share rejected");
    }
    if compositor::push_scene_submit(
        compositor_port,
        1,
        handle as u64,
        0,
        0,
        width,
        height,
        OVERLAY_Z,
    )
    .is_err()
    {
        let _ = mk_surface_release(handle as u64);
        let _ = mk_surface_release(handle as u64);
        return Err("compositor scene submit failed");
    }
    Ok(ctx)
}
