use crate::state::Context;

const LOCKED_BG: u32 = 0xFF24_2A36;
const UNLOCKED_BG: u32 = 0xFF14_3A22;
const BAR_COLOR: u32 = 0xFFED_CB68;

pub fn paint_locked(ctx: &Context) {
    fill(ctx.backing_va, ctx.width, ctx.height, ctx.stride, LOCKED_BG);
    paint_bar(ctx, 0x20);
}

pub fn paint_unlocked(ctx: &Context) {
    fill(ctx.backing_va, ctx.width, ctx.height, ctx.stride, UNLOCKED_BG);
    paint_bar(ctx, 0x38);
}

fn paint_bar(ctx: &Context, top: u32) {
    if ctx.width < 32 || ctx.height < top + 16 {
        return;
    }
    let start_x = 16u32;
    let end_x = ctx.width.saturating_sub(16);
    let y0 = top;
    let y1 = top + 8;
    for y in y0..y1 {
        for x in start_x..end_x {
            let px = unsafe { pixel_mut(ctx.backing_va, ctx.stride, x, y) };
            unsafe { core::ptr::write_volatile(px, BAR_COLOR); }
        }
    }
}

fn fill(base: u64, width: u32, height: u32, stride: u32, argb: u32) {
    for y in 0..height {
        for x in 0..width {
            let px = unsafe { pixel_mut(base, stride, x, y) };
            unsafe { core::ptr::write_volatile(px, argb); }
        }
    }
}

unsafe fn pixel_mut(base: u64, stride: u32, x: u32, y: u32) -> *mut u32 {
    (base as usize + y as usize * stride as usize + x as usize * 4) as *mut u32
}
