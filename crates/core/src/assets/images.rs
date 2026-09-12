//! Conversion of PNG artwork into the raw, uncompressed TGA textures the Wii U menu expects.
//!
//! The console loads four fixed-size textures per title. Each is a truecolor,
//! bottom-up TGA 2.0 file with no compression; we hand-write the format rather than use
//! `image`'s TGA encoder so the origin, channel order and footer match exactly.

use image::imageops::FilterType;

use crate::error::{Error, Result};

/// TGA 2.0 footer signature required by the format.
const TGA_FOOTER_SIGNATURE: &[u8; 18] = b"TRUEVISION-XFILE.\0";

/// One of the four boot/menu textures a Wii U title carries in `meta/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootTexture {
    /// The 128x128 title icon shown in the Wii U menu.
    Icon,
    /// The 1280x720 TV boot splash.
    BootTv,
    /// The 854x480 GamePad boot splash.
    BootDrc,
    /// The 170x42 logo shown during boot.
    BootLogo,
}

impl BootTexture {
    /// Pixel dimensions `(width, height)` the console expects for this texture.
    pub fn dims(self) -> (u32, u32) {
        match self {
            BootTexture::Icon => (128, 128),
            BootTexture::BootTv => (1280, 720),
            BootTexture::BootDrc => (854, 480),
            BootTexture::BootLogo => (170, 42),
        }
    }

    /// Bits per pixel: 32 (BGRA) for textures with alpha, 24 (BGR) otherwise.
    pub fn bpp(self) -> u8 {
        match self {
            BootTexture::Icon | BootTexture::BootLogo => 32,
            BootTexture::BootTv | BootTexture::BootDrc => 24,
        }
    }

    /// The `meta/` filename this texture is stored under.
    pub fn filename(self) -> &'static str {
        match self {
            BootTexture::Icon => "iconTex.tga",
            BootTexture::BootTv => "bootTvTex.tga",
            BootTexture::BootDrc => "bootDrcTex.tga",
            BootTexture::BootLogo => "bootLogoTex.tga",
        }
    }
}

/// Largest artwork dimension (in pixels) accepted from a PNG, per axis.
///
/// Every texture we produce is at most 1280x720, so anything remotely this large is already far
/// beyond useful — the cap exists to stop a hostile or corrupt PNG header (artwork can come from
/// a user-supplied file *or* a download) from making the decoder allocate for a multi-gigapixel
/// image before anything notices.
const MAX_SOURCE_DIM: u32 = 8192;

/// Largest total allocation the PNG decoder may make (256 MiB). 8192x8192 RGBA is 256 MiB, so
/// this is the matching bound on the other axis of the same attack: a header that stays under the
/// dimension caps but still asks for an enormous buffer.
const MAX_DECODE_ALLOC: u64 = 256 << 20;

/// Decode a PNG (or any format `image` guesses from the bytes) under explicit resource limits.
///
/// `image::load_from_memory` applies no dimension cap at all, so a 16-byte IHDR claiming
/// 60000x60000 is enough to drive a huge allocation. Going through `ImageReader` lets us install
/// [`Limits`](image::Limits) *before* the decode, so an oversized header is rejected as an error
/// instead.
fn decode_limited(png_bytes: &[u8]) -> Result<image::DynamicImage> {
    let mut reader = image::ImageReader::new(std::io::Cursor::new(png_bytes))
        .with_guessed_format()
        .map_err(|e| Error::Other(anyhow::anyhow!("failed to read PNG header: {e}")))?;
    // `Limits` is `#[non_exhaustive]`, so it can only be built by mutating the default (which
    // already caps `max_alloc`); that also means any limit added by a future `image` release
    // keeps its default rather than being silently disabled.
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_SOURCE_DIM);
    limits.max_image_height = Some(MAX_SOURCE_DIM);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);
    reader.limits(limits);
    reader
        .decode()
        .map_err(|e| Error::Other(anyhow::anyhow!("failed to decode PNG: {e}")))
}

/// Decode `png_bytes`, resize it to exactly `tex`'s dimensions, and hand-encode it as an
/// uncompressed, bottom-up TGA in the pixel format the console expects (BGR for 24bpp
/// textures, BGRA for 32bpp textures).
pub fn png_to_tga(png_bytes: &[u8], tex: BootTexture) -> Result<Vec<u8>> {
    let img = decode_limited(png_bytes)?;

    let (width, height) = tex.dims();
    let resized = img.resize_exact(width, height, FilterType::Lanczos3);
    let rgba = resized.to_rgba8();

    let bpp = tex.bpp();
    let bytes_per_pixel = (bpp / 8) as usize;
    let mut pixels = Vec::with_capacity(width as usize * height as usize * bytes_per_pixel);

    // TGA pixel data is bottom-up: emit rows from the last image row to the first.
    for y in (0..height).rev() {
        for x in 0..width {
            let p = rgba.get_pixel(x, y).0;
            pixels.push(p[2]); // B
            pixels.push(p[1]); // G
            pixels.push(p[0]); // R
            if bytes_per_pixel == 4 {
                pixels.push(p[3]); // A
            }
        }
    }

    let mut out = Vec::with_capacity(18 + pixels.len() + 26);
    out.push(0); // id length
    out.push(0); // color map type
    out.push(2); // image type: uncompressed truecolor
    out.extend_from_slice(&[0u8; 5]); // color map spec
    out.extend_from_slice(&0u16.to_le_bytes()); // x origin
    out.extend_from_slice(&0u16.to_le_bytes()); // y origin
    out.extend_from_slice(&(width as u16).to_le_bytes());
    out.extend_from_slice(&(height as u16).to_le_bytes());
    out.push(bpp);
    out.push(if bpp == 32 { 0x08 } else { 0x00 }); // image descriptor: alpha bits / origin
    out.extend_from_slice(&pixels);
    out.extend_from_slice(&0u32.to_le_bytes()); // extension area offset
    out.extend_from_slice(&0u32.to_le_bytes()); // developer directory offset
    out.extend_from_slice(TGA_FOOTER_SIGNATURE);

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgba};
    use std::io::Cursor;

    fn solid_red_png() -> Vec<u8> {
        let img: ImageBuffer<Rgba<u8>, Vec<u8>> =
            ImageBuffer::from_pixel(4, 4, Rgba([255, 0, 0, 255]));
        let mut bytes = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
            .expect("encode png");
        bytes
    }

    fn assert_header(data: &[u8], tex: BootTexture) {
        let (w, h) = tex.dims();
        let bpp = tex.bpp();
        assert_eq!(data[0], 0, "id length");
        assert_eq!(data[1], 0, "color map type");
        assert_eq!(data[2], 2, "image type");
        assert_eq!(&data[3..8], &[0u8; 5], "color map spec");
        assert_eq!(u16::from_le_bytes([data[8], data[9]]), 0, "x origin");
        assert_eq!(u16::from_le_bytes([data[10], data[11]]), 0, "y origin");
        assert_eq!(u16::from_le_bytes([data[12], data[13]]), w as u16, "width");
        assert_eq!(u16::from_le_bytes([data[14], data[15]]), h as u16, "height");
        assert_eq!(data[16], bpp, "bpp");
        let expected_desc = if bpp == 32 { 0x08 } else { 0x00 };
        assert_eq!(data[17], expected_desc, "image descriptor");

        let expected_len = 18 + (w as usize * h as usize * (bpp as usize / 8)) + 26;
        assert_eq!(data.len(), expected_len, "total length");

        let footer = &data[data.len() - 18..];
        assert_eq!(footer, TGA_FOOTER_SIGNATURE, "footer signature");
    }

    #[test]
    fn icon_texture_matches_format() {
        let png = solid_red_png();
        let tga = png_to_tga(&png, BootTexture::Icon).expect("convert");
        assert_header(&tga, BootTexture::Icon);
        // Solid red -> BGRA = 00 00 FF FF for every pixel, including the first.
        assert_eq!(&tga[18..22], &[0x00, 0x00, 0xFF, 0xFF]);
    }

    #[test]
    fn boot_tv_texture_matches_format() {
        let png = solid_red_png();
        let tga = png_to_tga(&png, BootTexture::BootTv).expect("convert");
        assert_header(&tga, BootTexture::BootTv);
        assert_eq!(&tga[18..21], &[0x00, 0x00, 0xFF]);
    }

    #[test]
    fn boot_drc_texture_matches_format() {
        let png = solid_red_png();
        let tga = png_to_tga(&png, BootTexture::BootDrc).expect("convert");
        assert_header(&tga, BootTexture::BootDrc);
        assert_eq!(&tga[18..21], &[0x00, 0x00, 0xFF]);
    }

    #[test]
    fn boot_logo_texture_matches_format() {
        let png = solid_red_png();
        let tga = png_to_tga(&png, BootTexture::BootLogo).expect("convert");
        assert_header(&tga, BootTexture::BootLogo);
        assert_eq!(&tga[18..22], &[0x00, 0x00, 0xFF, 0xFF]);
    }

    /// CRC-32 (IEEE, the PNG variant) over `data`, so the hand-built header below is a *valid*
    /// PNG chunk — otherwise the decoder would reject it on the checksum and the test would pass
    /// without ever exercising the limits.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    /// A PNG signature plus a well-formed IHDR declaring `width`x`height` 8-bit truecolor, and
    /// nothing else. Enough for the decoder to read the dimensions (and therefore to check them
    /// against the limits) without any image data at all.
    fn png_header_declaring(width: u32, height: u32) -> Vec<u8> {
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(b"IHDR");
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // bit depth, truecolor, deflate, adaptive, no interlace
        let mut out = Vec::new();
        out.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        out.extend_from_slice(&13u32.to_be_bytes());
        out.extend_from_slice(&ihdr);
        out.extend_from_slice(&crc32(&ihdr).to_be_bytes());
        out
    }

    /// A PNG whose header declares an absurd size must be rejected before the decoder allocates
    /// for it — `image::load_from_memory` would have happily tried (60000x60000 RGBA is ~13 GiB).
    #[test]
    fn oversized_png_header_is_rejected_by_the_decode_limits() {
        let png = png_header_declaring(60_000, 60_000);
        let err =
            png_to_tga(&png, BootTexture::Icon).expect_err("a 60000x60000 PNG must not be decoded");
        let msg = err.to_string();
        assert!(
            msg.contains("exceeds limit"),
            "the rejection must come from the decode limits, not from the truncated data: {msg}"
        );
    }

    /// The limits must not get in the way of ordinary artwork: a real (tiny) PNG still converts.
    #[test]
    fn small_real_png_still_converts_under_the_limits() {
        let img: ImageBuffer<Rgba<u8>, Vec<u8>> =
            ImageBuffer::from_pixel(2, 2, Rgba([0, 255, 0, 255]));
        let mut png = Vec::new();
        img.write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
            .expect("encode png");
        let tga = png_to_tga(&png, BootTexture::Icon).expect("a 2x2 PNG must convert");
        assert_header(&tga, BootTexture::Icon);
        // Solid green -> BGRA = 00 FF 00 FF.
        assert_eq!(&tga[18..22], &[0x00, 0xFF, 0x00, 0xFF]);
    }

    #[test]
    fn filenames_match_console_expectations() {
        assert_eq!(BootTexture::Icon.filename(), "iconTex.tga");
        assert_eq!(BootTexture::BootTv.filename(), "bootTvTex.tga");
        assert_eq!(BootTexture::BootDrc.filename(), "bootDrcTex.tga");
        assert_eq!(BootTexture::BootLogo.filename(), "bootLogoTex.tga");
    }
}
