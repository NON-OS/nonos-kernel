extern crate alloc;
use crate::viewer::caption::{interval_label, size_line, zoom_percent, KEYMAP};
use crate::viewer::state::ViewerState;
use crate::viewer::viewport::FitMode;
use alloc::format;
use alloc::string::String;
use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

const PANEL_W: u32 = 260;
const INFO_H: u32 = 60;

fn basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

fn ext_upper(path: &str) -> String {
    match path.rfind('.') {
        Some(i) => path[i + 1..].to_ascii_uppercase(),
        None => String::new(),
    }
}

fn mode_name(mode: FitMode) -> &'static str {
    match mode {
        FitMode::Fit => "FIT",
        FitMode::Actual => "ACTUAL",
        FitMode::Fill => "FILL",
    }
}

pub fn draw_info(fb: &mut PaintBuffer, st: &ViewerState) {
    if !st.info_visible {
        return;
    }
    let theme = roles();
    let ink = theme.text.argb();
    fb.blend_rect(0, 0, PANEL_W, INFO_H, theme.scrim.argb());
    let path = st.dir.get(st.idx).map(|p| p.as_str());
    fb.text(8, 6, path.map(basename).unwrap_or("(no image)").as_bytes(), ink);
    let dims = st.img.as_ref().map(|i| (i.w, i.h));
    let fmt = path.map(ext_upper).unwrap_or_default();
    fb.text(8, 24, size_line(dims, &fmt, st.file_size).as_bytes(), ink);
    let (iw, ih) = dims.unwrap_or((0, 0));
    let pct = zoom_percent(st.fit_mode, iw, ih, st.view_w, st.view_h, st.view.zoom);
    let line = format!("{}/{}  {}%  {}", st.idx + 1, st.dir.len(), pct, mode_name(st.fit_mode));
    fb.text(8, 42, line.as_bytes(), ink);
}

/// Below the info panel when both are open, so neither covers the other.
pub fn draw_help(fb: &mut PaintBuffer, st: &ViewerState) {
    if !st.help_visible {
        return;
    }
    let top = if st.info_visible { INFO_H + 4 } else { 0 };
    let h = 8 + KEYMAP.len() as u32 * 16;
    let theme = roles();
    let ink = theme.text.argb();
    fb.blend_rect(0, top, PANEL_W, h, theme.scrim.argb());
    for (i, (keys, action)) in KEYMAP.iter().enumerate() {
        fb.text(8, top + 6 + i as u32 * 16, format!("{}  {}", keys, action).as_bytes(), ink);
    }
}

pub fn draw_slideshow(fb: &mut PaintBuffer, st: &ViewerState) {
    if !st.slideshow_on {
        return;
    }
    let line = format!("> {}", interval_label(st.interval_ms));
    fb.text(fb.width.saturating_sub(60), 6, line.as_bytes(), roles().text.argb());
}
