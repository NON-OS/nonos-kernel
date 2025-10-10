// // src/text/mod.rs
// #![allow(dead_code)]
// extern crate alloc;

// use alloc::vec::Vec;
// use core::num::NonZeroU16;
// //use fontdue::{Font, FontSettings};
// use hashbrown::HashMap;

// /// Embedded fonts (place files at <repo>/fonts/*.ttf next to Cargo.toml)
// pub static INTER_SEMIBOLD_TTF: &[u8] = include_bytes!(concat!(
//     env!("CARGO_MANIFEST_DIR"),
//     "/fonts/Inter-SemiBold.ttf"
// ));
// pub static JBM_REGULAR_TTF: &[u8] = include_bytes!(concat!(
//     env!("CARGO_MANIFEST_DIR"),
//     "/fonts/JetBrainsMono-Regular.ttf"
// ));

// #[derive(Hash, Eq, PartialEq, Clone, Copy)]
// struct GlyphKey {
//     ch: char,
//     px: NonZeroU16,
//     mono: bool,
// }

// struct Glyph {
//     pub w: usize,
//     pub h: usize,
//     pub xmin: i32,
//     pub ymin: i32,
//     pub advance: f32,
//     pub alpha: Vec<u8>, // 8-bit coverage, row-major, stride == w
// }

// struct GlyphCache {
//     map: HashMap<GlyphKey, Glyph>,
// }

// impl GlyphCache {
//     fn new() -> Self {
//         Self { map: HashMap::new() }
//     }
// }

// pub struct TextCtx {
//     pub inter: Font, // proportional
//     pub mono: Font,  // JetBrains Mono
//     cache: GlyphCache,
// }

// impl TextCtx {
//     /// Load fonts from provided TTF bytes.
//     pub fn new(inter_bytes: &'static [u8], mono_bytes: &'static [u8]) -> Self {
//         let inter = Font::from_bytes(inter_bytes, FontSettings::default())
//             .expect("Inter font failed to load");
//         let mono = Font::from_bytes(mono_bytes, FontSettings::default())
//             .expect("JetBrainsMono font failed to load");
//         Self { inter, mono, cache: GlyphCache::new() }
//     }

//     /// Load fonts from the embedded includes above.
//     pub fn from_embedded() -> Self {
//         Self::new(INTER_SEMIBOLD_TTF, JBM_REGULAR_TTF)
//     }

//     /// Get (or rasterize and cache) a glyph bitmap for `ch` at `px` size.
//     /// Returns a reference valid as long as `self` is alive (cached inside).
//     pub fn raster_glyph(&mut self, ch: char, px: u16, use_mono: bool) -> &Glyph {
//         let key = GlyphKey { ch, px: NonZeroU16::new(px.max(1)).unwrap(), mono: use_mono };
//         if let Some(g) = self.cache.map.get(&key) {
//             return g;
//         }

//         let font = if use_mono { &self.mono } else { &self.inter };
//         let px_f = key.px.get() as f32;

//         // Advance width for layout
//         let metrics_adv = font.metrics(ch, px_f);
//         // Coverage bitmap and placement metrics
//         let (m, bitmap) = font.rasterize(ch, px_f);
//         let g = Glyph {
//             w: m.width,
//             h: m.height,
//             xmin: m.xmin,
//             ymin: m.ymin,
//             advance: metrics_adv.advance_width,
//             alpha: bitmap,
//         };
//         self.cache.map.insert(key, g);
//         self.cache.map.get(&key).unwrap()
//     }
// }
