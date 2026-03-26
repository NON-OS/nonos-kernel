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

//! Image loading pipeline: resolve URL, fetch bytes, detect format, decode.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use super::ImageData;

/// Maximum image download size (2 MiB).
const MAX_IMAGE_BYTES: usize = 2 * 1024 * 1024;

/// Maximum decoded dimension (consistent with PNG and JPEG decoders).
const MAX_DIMENSION: u32 = 4096;

/// Maximum number of images to load per page render.
const MAX_IMAGES_PER_PAGE: u32 = 8;

use core::sync::atomic::{AtomicU32, Ordering};

/// Counter for images loaded during the current render pass.
static IMAGE_LOAD_COUNT: AtomicU32 = AtomicU32::new(0);

/// Reset the per-page image counter. Call at the start of each render pass.
pub fn reset_image_count() {
    IMAGE_LOAD_COUNT.store(0, Ordering::Relaxed);
}

/// Detected image format based on magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    Jpeg,
    Png,
    Unknown,
}

/// Detect image format from the first bytes of data.
pub fn detect_image_format(data: &[u8]) -> ImageFormat {
    if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xD8 {
        ImageFormat::Jpeg
    } else if data.len() >= 8 && data[0..8] == *b"\x89PNG\r\n\x1a\n" {
        ImageFormat::Png
    } else {
        ImageFormat::Unknown
    }
}

/// Resolve a possibly-relative image `src` against a `base_url`.
///
/// Handles four forms:
/// - Absolute: `https://example.com/img.jpg` → returned as-is
/// - Protocol-relative: `//cdn.example.com/img.jpg` → inherits scheme from base
/// - Absolute path: `/images/logo.png` → origin from base + path
/// - Relative path: `img/photo.jpg` → base directory + path
///
/// Returns `None` if resolution fails.
pub fn resolve_url(src: &str, base_url: &str) -> Option<String> {
    let src = src.trim();
    if src.is_empty() {
        return None;
    }

    // Already absolute
    if src.starts_with("http://") || src.starts_with("https://") {
        return Some(String::from(src));
    }

    // Data URIs are not fetchable
    if src.starts_with("data:") {
        return None;
    }

    // Protocol-relative
    if src.starts_with("//") {
        let scheme = if base_url.starts_with("https") { "https:" } else { "http:" };
        return Some(alloc::format!("{}{}", scheme, src));
    }

    // Absolute path — extract origin from base_url
    if src.starts_with('/') {
        let origin = extract_origin(base_url)?;
        return Some(alloc::format!("{}{}", origin, src));
    }

    // Relative path — extract base directory
    let base_path = extract_base_path(base_url)?;
    Some(alloc::format!("{}{}", base_path, src))
}

/// Extract the origin (scheme + host + port) from a URL.
/// e.g. `https://example.com:8080/path/page` → `https://example.com:8080`
fn extract_origin(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let after_scheme = scheme_end + 3;
    let host_end = url[after_scheme..].find('/').map(|i| i + after_scheme).unwrap_or(url.len());
    Some(String::from(&url[..host_end]))
}

/// Extract the base directory path (up to and including the last `/`).
/// e.g. `https://example.com/dir/page.html` → `https://example.com/dir/`
fn extract_base_path(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let after_scheme = scheme_end + 3;
    // Find the path start (first `/` after the host)
    let path_start = url[after_scheme..].find('/').map(|i| i + after_scheme)?;
    // Find last `/` in the path
    let last_slash = url[path_start..].rfind('/').map(|i| i + path_start)?;
    Some(String::from(&url[..last_slash + 1]))
}

/// Fetch image bytes from the given absolute URL.
///
/// Uses the HTTP client with a size limit. Returns `None` on failure or
/// if the response exceeds `MAX_IMAGE_BYTES`.
fn fetch_image_bytes(url: &str) -> Option<Vec<u8>> {
    // Only HTTP/HTTPS URLs are supported
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return None;
    }

    let response = crate::network::http_client::fetch_response(url).ok()?;

    if !response.is_success() {
        return None;
    }

    // Enforce size limit
    if response.body.len() > MAX_IMAGE_BYTES {
        return None;
    }

    Some(response.body)
}

/// Load and decode an image from a (possibly relative) `src` URL.
///
/// Resolves the URL against `base_url`, fetches the bytes, detects the format
/// via magic bytes, and decodes to `ImageData`. Returns `None` on any failure.
pub fn load_image(src: &str, base_url: &str) -> Option<ImageData> {
    // Enforce per-page image limit
    let count = IMAGE_LOAD_COUNT.fetch_add(1, Ordering::Relaxed);
    if count >= MAX_IMAGES_PER_PAGE {
        return None;
    }

    let url = resolve_url(src, base_url)?;
    let data = fetch_image_bytes(&url)?;

    let image = match detect_image_format(&data) {
        ImageFormat::Jpeg => super::decode_jpeg(&data),
        ImageFormat::Png => super::decode_png(&data),
        ImageFormat::Unknown => None,
    }?;

    // Enforce dimension limit
    if image.width > MAX_DIMENSION || image.height > MAX_DIMENSION {
        return None;
    }

    Some(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- resolve_url tests ---

    #[test]
    fn test_resolve_absolute_url() {
        let result = resolve_url("https://cdn.example.com/img.jpg", "https://example.com/page");
        assert_eq!(result, Some(String::from("https://cdn.example.com/img.jpg")));
    }

    #[test]
    fn test_resolve_absolute_http() {
        let result = resolve_url("http://other.com/pic.png", "https://example.com/page");
        assert_eq!(result, Some(String::from("http://other.com/pic.png")));
    }

    #[test]
    fn test_resolve_protocol_relative() {
        let result = resolve_url("//cdn.example.com/img.jpg", "https://example.com/page");
        assert_eq!(result, Some(String::from("https://cdn.example.com/img.jpg")));
    }

    #[test]
    fn test_resolve_protocol_relative_http() {
        let result = resolve_url("//cdn.example.com/img.jpg", "http://example.com/page");
        assert_eq!(result, Some(String::from("http://cdn.example.com/img.jpg")));
    }

    #[test]
    fn test_resolve_absolute_path() {
        let result = resolve_url("/images/logo.png", "https://example.com/dir/page.html");
        assert_eq!(result, Some(String::from("https://example.com/images/logo.png")));
    }

    #[test]
    fn test_resolve_absolute_path_with_port() {
        let result = resolve_url("/img.png", "https://example.com:8080/page");
        assert_eq!(result, Some(String::from("https://example.com:8080/img.png")));
    }

    #[test]
    fn test_resolve_relative_path() {
        let result = resolve_url("photo.jpg", "https://example.com/gallery/index.html");
        assert_eq!(result, Some(String::from("https://example.com/gallery/photo.jpg")));
    }

    #[test]
    fn test_resolve_relative_subdir() {
        let result = resolve_url("img/pic.png", "https://example.com/dir/page.html");
        assert_eq!(result, Some(String::from("https://example.com/dir/img/pic.png")));
    }

    #[test]
    fn test_resolve_empty_src() {
        let result = resolve_url("", "https://example.com/page");
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_data_uri() {
        let result = resolve_url("data:image/png;base64,abc", "https://example.com/page");
        assert_eq!(result, None);
    }

    // --- detect_image_format tests ---

    #[test]
    fn test_detect_jpeg() {
        let data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert_eq!(detect_image_format(&data), ImageFormat::Jpeg);
    }

    #[test]
    fn test_detect_png() {
        let data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        assert_eq!(detect_image_format(data), ImageFormat::Png);
    }

    #[test]
    fn test_detect_unknown() {
        let data = [0x47, 0x49, 0x46, 0x38]; // GIF header
        assert_eq!(detect_image_format(&data), ImageFormat::Unknown);
    }

    #[test]
    fn test_detect_empty() {
        assert_eq!(detect_image_format(&[]), ImageFormat::Unknown);
    }

    #[test]
    fn test_detect_single_byte() {
        assert_eq!(detect_image_format(&[0xFF]), ImageFormat::Unknown);
    }

    // --- extract_origin / extract_base_path tests ---

    #[test]
    fn test_extract_origin() {
        assert_eq!(extract_origin("https://example.com/path/page"), Some(String::from("https://example.com")));
        assert_eq!(extract_origin("https://example.com:8080/page"), Some(String::from("https://example.com:8080")));
        assert_eq!(extract_origin("http://host"), Some(String::from("http://host")));
    }

    #[test]
    fn test_extract_base_path() {
        assert_eq!(
            extract_base_path("https://example.com/dir/page.html"),
            Some(String::from("https://example.com/dir/"))
        );
        assert_eq!(
            extract_base_path("https://example.com/a/b/c.html"),
            Some(String::from("https://example.com/a/b/"))
        );
    }

    // --- load_image tests (unit-testable parts) ---

    #[test]
    fn test_load_image_invalid_data_returns_none() {
        // Cannot call load_image in host tests (no network), but we can test
        // that detect + decode with garbage data returns None.
        let garbage = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let fmt = detect_image_format(&garbage);
        assert_eq!(fmt, ImageFormat::Unknown);
    }

    #[test]
    fn test_load_image_jpeg_bytes_decode() {
        // Build a minimal valid JPEG using the proven pattern from the jpeg
        // module tests and verify detect + decode works end-to-end.
        let jpeg = build_minimal_jpeg();
        assert_eq!(detect_image_format(&jpeg), ImageFormat::Jpeg);
        let result = super::super::decode_jpeg(&jpeg);
        assert!(result.is_some());
        let img = result.unwrap();
        assert_eq!(img.width, 8);
        assert_eq!(img.height, 8);
    }

    /// Build a minimal valid baseline JPEG (8×8, grayscale, DC=0).
    fn build_minimal_jpeg() -> Vec<u8> {
        let mut d = Vec::new();
        // SOI
        d.extend_from_slice(&[0xFF, 0xD8]);
        // DQT — all-ones quantization table (id=0)
        d.extend_from_slice(&[0xFF, 0xDB]);
        d.extend_from_slice(&67u16.to_be_bytes());
        d.push(0x00);
        for _ in 0..64 { d.push(1); }
        // SOF0 — baseline, 8×8, 1 component
        d.extend_from_slice(&[0xFF, 0xC0]);
        d.extend_from_slice(&11u16.to_be_bytes());
        d.push(8);
        d.extend_from_slice(&8u16.to_be_bytes());
        d.extend_from_slice(&8u16.to_be_bytes());
        d.push(1); d.push(1); d.push(0x11); d.push(0);
        // DHT — DC table: symbol 0 with code '0'
        d.extend_from_slice(&[0xFF, 0xC4]);
        d.extend_from_slice(&20u16.to_be_bytes());
        d.push(0x00);
        d.push(1); for _ in 1..16 { d.push(0); }
        d.push(0x00);
        // DHT — AC table: symbol 0x00 (EOB) with code '0'
        d.extend_from_slice(&[0xFF, 0xC4]);
        d.extend_from_slice(&20u16.to_be_bytes());
        d.push(0x10);
        d.push(1); for _ in 1..16 { d.push(0); }
        d.push(0x00);
        // SOS
        d.extend_from_slice(&[0xFF, 0xDA]);
        d.extend_from_slice(&8u16.to_be_bytes());
        d.push(1); d.push(1); d.push(0x00);
        d.push(0); d.push(63); d.push(0);
        // Entropy: DC=0 (1 bit), AC EOB (1 bit), padded to byte
        d.push(0x00);
        // EOI
        d.extend_from_slice(&[0xFF, 0xD9]);
        d
    }
}
