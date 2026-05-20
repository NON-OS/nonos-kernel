pub fn render_matrix_argb8888(
    matrix: &[u8],
    size: u8,
    scale: u8,
    on: u32,
    off: u32,
    buf: &mut [u32],
    stride: usize,
    w: u32,
    h: u32,
) -> bool {
    let size = size as usize;
    let scale = scale.max(1) as usize;
    if matrix.len() < size.saturating_mul(size) {
        return false;
    }
    let need_w = size.saturating_mul(scale);
    let need_h = size.saturating_mul(scale);
    if (w as usize) < need_w || (h as usize) < need_h {
        return false;
    }
    let mut my = 0usize;
    while my < size {
        let mut mx = 0usize;
        while mx < size {
            let color = if matrix[my * size + mx] != 0 { on } else { off };
            let mut py = 0usize;
            while py < scale {
                let mut px = 0usize;
                while px < scale {
                    let x = mx * scale + px;
                    let y = my * scale + py;
                    let i = y.saturating_mul(stride).saturating_add(x);
                    if i < buf.len() {
                        buf[i] = color;
                    }
                    px += 1;
                }
                py += 1;
            }
            mx += 1;
        }
        my += 1;
    }
    true
}
