# NØNOS Desktop Wallpapers

## Artist Credit

All wallpapers in this collection were created by **Eric Jordan** ([ericjordan.com](https://ericjordan.com)).

These original artworks were commissioned specifically for the NØNOS operating system and represent the visual identity of the desktop environment.

## Collection Overview

The wallpaper collection consists of 33 unique designs organized into four categories:

### Network Topology (11 wallpapers)
Abstract visualizations inspired by network structures and digital connectivity. These serve as the default system style, reflecting NØNOS focus on secure, connected computing.

- `network-topology-1.png` through `network-topology-11.png`

### Field + Focus (5 wallpapers)
Minimalist compositions exploring depth of field and spatial relationships. Clean, professional designs suitable for productivity-focused users.

- `field-focus-1.png` through `field-focus-5.png`

### Hardware Aesthetic (7 wallpapers)
Designs inspired by computing hardware, silicon architecture, and the physical reality of digital systems. A nod to the bare-metal nature of the NØNOS kernel.

- `hardware-aesthetic-1.png` through `hardware-aesthetic-7.png`

### Special Variants (10 wallpapers)
Unique interpretations and experimental pieces that complement the core collection with distinctive visual treatments.

- `special-variant-1a.png`, `special-variant-1b.png`
- `special-variant-2a.png`, `special-variant-2b.png`
- `special-variant-3.png` through `special-variant-8.png`

## Integration with NØNOS-kernel

The wallpaper system is implemented in the kernel graphics subsystem:

**Catalog Definition**: `src/graphics/backgrounds/wallpaper.rs`
- Defines the `WallpaperCategory` enum and `WallpaperInfo` struct
- Maintains the complete catalog of all 33 wallpapers
- Handles wallpaper loading, caching and selection state

**Settings Interface**: `src/graphics/window/settings/appearance/`
- Users can browse wallpapers by category in the Settings app
- Wallpaper previews are displayed in a grid layout
- Selection is instant with automatic caching of the decoded image

**Runtime Behavior**:
1. At boot, the system defaults to a procedural gradient background
2. Users can select any wallpaper through Settings > Appearance > Wallpapers
3. Selected wallpapers are loaded from `/sys/assets/wallpapers/` and decoded as PNG
4. The decoded image is cached in memory to avoid repeated disk access
5. Wallpapers scale to fit the display resolution

## File Format

All wallpapers are stored as PNG files. The kernel built-in PNG decoder handles the images without external dependencies, making the wallpaper system fully self-contained within the kernel binary when bundled into the system image.

## License

The wallpaper artwork is included in NØNOS under arrangement with the artist. For licensing inquiries regarding use outside of NØNOS, please contact Eric Jordan directly through [ericjordan.com](https://ericjordan.com).
