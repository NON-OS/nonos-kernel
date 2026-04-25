use crate::graphics::image::types::DecodedImage;
use crate::test::framework::TestResult;
use alloc::vec;

pub(crate) fn test_decoded_image_new() -> TestResult {
    let pixels = vec![0xFFFFFFFF; 16];
    let img = DecodedImage::new(4, 4, pixels);
    if img.width != 4 {
        return TestResult::Fail;
    }
    if img.height != 4 {
        return TestResult::Fail;
    }
    if img.pixels.len() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_decoded_image_empty() -> TestResult {
    let pixels = vec![];
    let img = DecodedImage::new(0, 0, pixels);
    if img.width != 0 {
        return TestResult::Fail;
    }
    if img.height != 0 {
        return TestResult::Fail;
    }
    if !img.pixels.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_decoded_image_get_pixel() -> TestResult {
    let pixels = vec![0xFF000000, 0xFF0000FF, 0xFF00FF00, 0xFFFF0000];
    let img = DecodedImage::new(2, 2, pixels);

    if img.get_pixel(0, 0) != Some(0xFF000000) {
        return TestResult::Fail;
    }
    if img.get_pixel(1, 0) != Some(0xFF0000FF) {
        return TestResult::Fail;
    }
    if img.get_pixel(0, 1) != Some(0xFF00FF00) {
        return TestResult::Fail;
    }
    if img.get_pixel(1, 1) != Some(0xFFFF0000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_decoded_image_get_pixel_out_of_bounds() -> TestResult {
    let pixels = vec![0xFFFFFFFF; 4];
    let img = DecodedImage::new(2, 2, pixels);

    if img.get_pixel(2, 0) != None {
        return TestResult::Fail;
    }
    if img.get_pixel(0, 2) != None {
        return TestResult::Fail;
    }
    if img.get_pixel(2, 2) != None {
        return TestResult::Fail;
    }
    if img.get_pixel(100, 100) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_decoded_image_get_pixel_boundary() -> TestResult {
    let pixels = vec![0xFF123456; 9];
    let img = DecodedImage::new(3, 3, pixels);

    if img.get_pixel(0, 0) != Some(0xFF123456) {
        return TestResult::Fail;
    }
    if img.get_pixel(2, 0) != Some(0xFF123456) {
        return TestResult::Fail;
    }
    if img.get_pixel(0, 2) != Some(0xFF123456) {
        return TestResult::Fail;
    }
    if img.get_pixel(2, 2) != Some(0xFF123456) {
        return TestResult::Fail;
    }

    if img.get_pixel(3, 0) != None {
        return TestResult::Fail;
    }
    if img.get_pixel(0, 3) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_decoded_image_dimensions() -> TestResult {
    let img = DecodedImage::new(100, 50, vec![0u32; 5000]);
    if img.width != 100 {
        return TestResult::Fail;
    }
    if img.height != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_decoded_image_pixel_count() -> TestResult {
    let width = 10u32;
    let height = 20u32;
    let pixels = vec![0u32; (width * height) as usize];
    let img = DecodedImage::new(width, height, pixels);
    if img.pixels.len() != (width * height) as usize {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_decoded_image_clone() -> TestResult {
    let pixels = vec![0xFF112233, 0xFF445566, 0xFF778899, 0xFFAABBCC];
    let img = DecodedImage::new(2, 2, pixels);
    let cloned = img.clone();

    if cloned.width != img.width {
        return TestResult::Fail;
    }
    if cloned.height != img.height {
        return TestResult::Fail;
    }
    if cloned.pixels != img.pixels {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_decoded_image_pixel_layout() -> TestResult {
    let pixels = vec![1, 2, 3, 4, 5, 6];
    let img = DecodedImage::new(3, 2, pixels);

    if img.get_pixel(0, 0) != Some(1) {
        return TestResult::Fail;
    }
    if img.get_pixel(1, 0) != Some(2) {
        return TestResult::Fail;
    }
    if img.get_pixel(2, 0) != Some(3) {
        return TestResult::Fail;
    }
    if img.get_pixel(0, 1) != Some(4) {
        return TestResult::Fail;
    }
    if img.get_pixel(1, 1) != Some(5) {
        return TestResult::Fail;
    }
    if img.get_pixel(2, 1) != Some(6) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_decoded_image_large() -> TestResult {
    let width = 256u32;
    let height = 256u32;
    let pixels = vec![0xFFFFFFFF; (width * height) as usize];
    let img = DecodedImage::new(width, height, pixels);

    if img.width != 256 {
        return TestResult::Fail;
    }
    if img.height != 256 {
        return TestResult::Fail;
    }
    if img.get_pixel(0, 0) != Some(0xFFFFFFFF) {
        return TestResult::Fail;
    }
    if img.get_pixel(255, 255) != Some(0xFFFFFFFF) {
        return TestResult::Fail;
    }
    if img.get_pixel(256, 0) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_decoded_image_single_pixel() -> TestResult {
    let pixels = vec![0xDEADBEEF];
    let img = DecodedImage::new(1, 1, pixels);

    if img.width != 1 {
        return TestResult::Fail;
    }
    if img.height != 1 {
        return TestResult::Fail;
    }
    if img.get_pixel(0, 0) != Some(0xDEADBEEF) {
        return TestResult::Fail;
    }
    if img.get_pixel(1, 0) != None {
        return TestResult::Fail;
    }
    if img.get_pixel(0, 1) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_decoded_image_row_major() -> TestResult {
    let pixels = vec![0, 1, 2, 3, 4, 5];
    let img = DecodedImage::new(3, 2, pixels);

    for y in 0..2u32 {
        for x in 0..3u32 {
            let expected = y * 3 + x;
            if img.get_pixel(x, y) != Some(expected) {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_decoded_image_transparent_pixels() -> TestResult {
    let transparent = 0x00000000u32;
    let semi_transparent = 0x80FF0000u32;
    let opaque = 0xFFFF0000u32;

    let pixels = vec![transparent, semi_transparent, opaque, opaque];
    let img = DecodedImage::new(2, 2, pixels);

    let p0 = img.get_pixel(0, 0).unwrap();
    let p1 = img.get_pixel(1, 0).unwrap();
    let p2 = img.get_pixel(0, 1).unwrap();

    if (p0 >> 24) & 0xFF != 0x00 {
        return TestResult::Fail;
    }
    if (p1 >> 24) & 0xFF != 0x80 {
        return TestResult::Fail;
    }
    if (p2 >> 24) & 0xFF != 0xFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}
