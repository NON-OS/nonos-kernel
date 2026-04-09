use super::metrics::FontMetrics;
use super::matching::FontFamily;

pub fn builtin_metrics(family: FontFamily) -> FontMetrics {
    match family {
        FontFamily::Monospace => FontMetrics {
            char_width: 8, char_height: 16, ascent: 12, descent: 4, line_height: 18,
        },
        FontFamily::SansSerif => FontMetrics {
            char_width: 7, char_height: 16, ascent: 12, descent: 4, line_height: 18,
        },
        FontFamily::Serif => FontMetrics {
            char_width: 7, char_height: 16, ascent: 13, descent: 3, line_height: 18,
        },
    }
}
