use crate::viewer::caption::nav_shown;
use crate::viewer::nav::{button_rects, BTN_H, BTN_W};
use crate::viewer::overlay;
use crate::viewer::scale::{draw_bilinear, draw_nn, Dst};
use crate::viewer::state::ViewerState;
use crate::viewer::viewport::{clamp_pan_mode, place_mode, FitMode};
use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

pub fn paint(st: &mut ViewerState, fb: &mut PaintBuffer) {
    st.view_w = fb.width;
    st.view_h = fb.height;
    fb.fill_rect(0, 0, fb.width, fb.height, roles().bg.argb());
    match st.img.as_ref() {
        Some(img) => {
            clamp_pan_mode(&mut st.view, st.fit_mode, img.w, img.h, fb.width, fb.height);
            let p = place_mode(st.fit_mode, img.w, img.h, fb.width, fb.height, &st.view);
            let (w, h, stride) = (fb.width, fb.height, fb.stride_words);
            let mut dst = Dst { px: fb.pixels, stride, w, h };
            if st.fit_mode == FitMode::Actual && st.view.zoom == 1.0 {
                draw_nn(&mut dst, &img.px, img.w, img.h, p.dx, p.dy, p.dw, p.dh);
            } else {
                draw_bilinear(&mut dst, &img.px, img.w, img.h, p.dx, p.dy, p.dw, p.dh);
            }
        }
        None => {}
    }
    if !st.status.is_empty() {
        fb.text(8, fb.height.saturating_sub(20), st.status.as_bytes(), roles().text.argb());
    }
    overlay::draw_info(fb, st);
    overlay::draw_help(fb, st);
    overlay::draw_slideshow(fb, st);
    paint_nav(fb, st);
}

fn paint_nav(fb: &mut PaintBuffer, st: &ViewerState) {
    if !nav_shown(st.dir.len()) {
        return;
    }
    let (l, r) = button_rects(fb.width, fb.height);
    let theme = roles();
    let (scrim, ink) = (theme.scrim.argb(), theme.text.argb());
    fb.blend_rect(l.x as u32, l.y as u32, l.w, l.h, scrim);
    fb.blend_rect(r.x as u32, r.y as u32, r.w, r.h, scrim);
    let ty = l.y as u32 + BTN_H / 2 - 4;
    fb.text(l.x as u32 + BTN_W / 2 - 4, ty, b"<", ink);
    fb.text(r.x as u32 + BTN_W / 2 - 4, ty, b">", ink);
}
