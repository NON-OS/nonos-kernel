// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! Every chrome text token reads on every ground it is drawn on at 4.5:1 or
//! better (WCAG 2 AA for body text), under both the light and dark palette.

use crate::browser::tokens::{Palette, DARK, LIGHT};

const AA: f64 = 4.5;

fn channel(c: u32, shift: u32) -> f64 {
    let v = ((c >> shift) & 0xff) as f64 / 255.0;
    if v <= 0.039_28 {
        v / 12.92
    } else {
        ((v + 0.055) / 1.055).powf(2.4)
    }
}

/// WCAG relative luminance of an opaque ARGB colour.
fn luminance(c: u32) -> f64 {
    0.2126 * channel(c, 16) + 0.7152 * channel(c, 8) + 0.0722 * channel(c, 0)
}

/// WCAG contrast ratio between two colours, from 1 to 21.
fn contrast(a: u32, b: u32) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

fn pairs(p: &Palette) -> Vec<(&'static str, u32, &'static str, u32)> {
    let texts = [("ink", p.ink), ("ink2", p.ink2), ("muted", p.muted)];
    let grounds =
        [("ground", p.ground), ("surface", p.surface), ("sidebar", p.sidebar), ("field", p.field)];
    let mut out = Vec::new();
    for (tn, t) in texts {
        for (gn, g) in grounds {
            out.push((tn, t, gn, g));
        }
    }
    out.push(("on_accent", p.on_accent, "accent", p.accent));
    out.push(("teal", p.teal, "surface", p.surface));
    out.push(("warn", p.warn, "warn_soft", p.warn_soft));
    out
}

fn all_read(name: &str, p: &Palette) {
    for (tn, t, gn, g) in pairs(p) {
        let r = contrast(t, g);
        assert!(r >= AA, "{name}: {tn} on {gn} is {r:.2}:1");
    }
}

#[test]
fn the_ratio_matches_the_wcag_reference_points() {
    assert!((contrast(0xFF00_0000, 0xFFFF_FFFF) - 21.0).abs() < 1e-9);
    assert!((contrast(0xFF77_7777, 0xFF77_7777) - 1.0).abs() < 1e-9);
    assert!((contrast(0xFF76_7676, 0xFFFF_FFFF) - 4.54).abs() < 0.01);
}

#[test]
fn light_text_tokens_meet_aa_on_their_grounds() {
    all_read("light", &LIGHT);
}

#[test]
fn dark_text_tokens_meet_aa_on_their_grounds() {
    all_read("dark", &DARK);
}
