use crate::design::color::Argb;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToggleStyle {
    pub on_track: Argb,
    pub off_track: Argb,
    pub knob: Argb,
}

impl Default for ToggleStyle {
    fn default() -> Self {
        Self {
            on_track: Argb::from_channels(0xFF, 0x3A, 0x9E, 0x66),
            off_track: Argb::from_channels(0xFF, 0x36, 0x3D, 0x49),
            knob: Argb::from_channels(0xFF, 0xF4, 0xF7, 0xFB),
        }
    }
}

pub fn toggle_track(enabled: bool, style: ToggleStyle) -> u32 {
    if enabled {
        style.on_track.as_u32()
    } else {
        style.off_track.as_u32()
    }
}
