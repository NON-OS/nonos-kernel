use alloc::vec;
use crate::graphics::image::types::DecodedImage;

#[test]
fn test_decoded_image_new() {
    let pixels = vec![0xFFFFFFFF; 16];
    let img = DecodedImage::new(4, 4, pixels);
    assert_eq!(img.width, 4);
    assert_eq!(img.height, 4);
    assert_eq!(img.pixels.len(), 16);
}

#[test]
fn test_decoded_image_empty() {
    let pixels = vec![];
    let img = DecodedImage::new(0, 0, pixels);
    assert_eq!(img.width, 0);
    assert_eq!(img.height, 0);
    assert!(img.pixels.is_empty());
}

#[test]
fn test_decoded_image_get_pixel() {
    let pixels = vec![
        0xFF000000, 0xFF0000FF, 0xFF00FF00, 0xFFFF0000,
    ];
    let img = DecodedImage::new(2, 2, pixels);

    assert_eq!(img.get_pixel(0, 0), Some(0xFF000000));
    assert_eq!(img.get_pixel(1, 0), Some(0xFF0000FF));
    assert_eq!(img.get_pixel(0, 1), Some(0xFF00FF00));
    assert_eq!(img.get_pixel(1, 1), Some(0xFFFF0000));
}

#[test]
fn test_decoded_image_get_pixel_out_of_bounds() {
    let pixels = vec![0xFFFFFFFF; 4];
    let img = DecodedImage::new(2, 2, pixels);

    assert_eq!(img.get_pixel(2, 0), None);
    assert_eq!(img.get_pixel(0, 2), None);
    assert_eq!(img.get_pixel(2, 2), None);
    assert_eq!(img.get_pixel(100, 100), None);
}

#[test]
fn test_decoded_image_get_pixel_boundary() {
    let pixels = vec![0xFF123456; 9];
    let img = DecodedImage::new(3, 3, pixels);

    assert_eq!(img.get_pixel(0, 0), Some(0xFF123456));
    assert_eq!(img.get_pixel(2, 0), Some(0xFF123456));
    assert_eq!(img.get_pixel(0, 2), Some(0xFF123456));
    assert_eq!(img.get_pixel(2, 2), Some(0xFF123456));

    assert_eq!(img.get_pixel(3, 0), None);
    assert_eq!(img.get_pixel(0, 3), None);
}

#[test]
fn test_decoded_image_dimensions() {
    let img = DecodedImage::new(100, 50, vec![0u32; 5000]);
    assert_eq!(img.width, 100);
    assert_eq!(img.height, 50);
}

#[test]
fn test_decoded_image_pixel_count() {
    let width = 10u32;
    let height = 20u32;
    let pixels = vec![0u32; (width * height) as usize];
    let img = DecodedImage::new(width, height, pixels);
    assert_eq!(img.pixels.len(), (width * height) as usize);
}

#[test]
fn test_decoded_image_clone() {
    let pixels = vec![0xFF112233, 0xFF445566, 0xFF778899, 0xFFAABBCC];
    let img = DecodedImage::new(2, 2, pixels);
    let cloned = img.clone();

    assert_eq!(cloned.width, img.width);
    assert_eq!(cloned.height, img.height);
    assert_eq!(cloned.pixels, img.pixels);
}

#[test]
fn test_decoded_image_pixel_layout() {
    let pixels = vec![
        1, 2, 3,
        4, 5, 6,
    ];
    let img = DecodedImage::new(3, 2, pixels);

    assert_eq!(img.get_pixel(0, 0), Some(1));
    assert_eq!(img.get_pixel(1, 0), Some(2));
    assert_eq!(img.get_pixel(2, 0), Some(3));
    assert_eq!(img.get_pixel(0, 1), Some(4));
    assert_eq!(img.get_pixel(1, 1), Some(5));
    assert_eq!(img.get_pixel(2, 1), Some(6));
}

#[test]
fn test_decoded_image_large() {
    let width = 256u32;
    let height = 256u32;
    let pixels = vec![0xFFFFFFFF; (width * height) as usize];
    let img = DecodedImage::new(width, height, pixels);

    assert_eq!(img.width, 256);
    assert_eq!(img.height, 256);
    assert_eq!(img.get_pixel(0, 0), Some(0xFFFFFFFF));
    assert_eq!(img.get_pixel(255, 255), Some(0xFFFFFFFF));
    assert_eq!(img.get_pixel(256, 0), None);
}

#[test]
fn test_decoded_image_single_pixel() {
    let pixels = vec![0xDEADBEEF];
    let img = DecodedImage::new(1, 1, pixels);

    assert_eq!(img.width, 1);
    assert_eq!(img.height, 1);
    assert_eq!(img.get_pixel(0, 0), Some(0xDEADBEEF));
    assert_eq!(img.get_pixel(1, 0), None);
    assert_eq!(img.get_pixel(0, 1), None);
}

#[test]
fn test_decoded_image_row_major() {
    let pixels = vec![0, 1, 2, 3, 4, 5];
    let img = DecodedImage::new(3, 2, pixels);

    for y in 0..2u32 {
        for x in 0..3u32 {
            let expected = y * 3 + x;
            assert_eq!(img.get_pixel(x, y), Some(expected));
        }
    }
}

#[test]
fn test_decoded_image_transparent_pixels() {
    let transparent = 0x00000000u32;
    let semi_transparent = 0x80FF0000u32;
    let opaque = 0xFFFF0000u32;

    let pixels = vec![transparent, semi_transparent, opaque, opaque];
    let img = DecodedImage::new(2, 2, pixels);

    let p0 = img.get_pixel(0, 0).unwrap();
    let p1 = img.get_pixel(1, 0).unwrap();
    let p2 = img.get_pixel(0, 1).unwrap();

    assert_eq!((p0 >> 24) & 0xFF, 0x00);
    assert_eq!((p1 >> 24) & 0xFF, 0x80);
    assert_eq!((p2 >> 24) & 0xFF, 0xFF);
}
