use crate::font::glyph::{glyph_for_ascii, GlyphBitmap};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FontAtlas {
    pub glyph_width: u8,
    pub glyph_height: u8,
    pub letter_spacing: u8,
}

impl Default for FontAtlas {
    fn default() -> Self {
        Self { glyph_width: 8, glyph_height: 8, letter_spacing: 1 }
    }
}

impl FontAtlas {
    pub fn glyph(self, ascii: u8) -> &'static GlyphBitmap {
        glyph_for_ascii(ascii)
    }

    pub fn text_width(self, bytes: &[u8]) -> u32 {
        if bytes.is_empty() {
            return 0;
        }
        let gw = self.glyph_width as u32;
        let spacing = self.letter_spacing as u32;
        (bytes.len() as u32 * gw) + ((bytes.len() as u32 - 1) * spacing)
    }
}
