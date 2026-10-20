/* qwenui: glyphs blended over whatever is under them. */
#include "qwenglyphs.h"
#include "qwenui.h"

#include <cstring>

void ui_fill(Wl &w, int x, int y, int width, int height, uint32_t color) {
    for (int j = y < 0 ? 0 : y; j < y + height && j < w.h; j++)
        for (int i = x < 0 ? 0 : x; i < x + width && i < w.w; i++) w.px[j * w.w + i] = color;
}

static uint32_t blend(uint32_t under, uint32_t over, unsigned a) {
    uint32_t out = 0xFF000000;
    for (int s = 0; s < 24; s += 8) {
        unsigned u = (under >> s) & 0xFF, o = (over >> s) & 0xFF;
        out |= ((o * a + u * (255 - a)) / 255) << s;
    }
    return out;
}

/* One code point: ASCII as itself, anything the atlas lacks as '?'. */
static int next(const std::string &s, size_t &i) {
    unsigned char c = (unsigned char)s[i++];
    if (c < 0x80) return c;
    while (i < s.size() && ((unsigned char)s[i] & 0xC0) == 0x80) i++;
    return '?';
}

void ui_text(Wl &w, int x, int y, const std::string &s, uint32_t color) {
    for (size_t i = 0; i < s.size(); x += CELL_W) {
        int c = next(s, i);
        if (c < FIRST || c > LAST) c = ' ';
        for (int j = 0; j < CELL_H; j++) {
            int py = y + j;
            if (py < 0 || py >= w.h) continue;
            for (int k = 0; k < CELL_W; k++) {
                int px = x + k;
                unsigned a = glyph_alpha(c - FIRST, j, k);
                if (a && px >= 0 && px < w.w) w.px[py * w.w + px] = blend(w.px[py * w.w + px], color, a);
            }
        }
    }
}

void ui_wipe(Wl &w, View &v) {
    for (Said &s : v.said) memset(&s.text[0], 0, s.text.size());
    if (!v.input.empty()) memset(&v.input[0], 0, v.input.size());
    v.said.clear();
    v.input.clear();
    v.back = 0;
    memset(w.px, 0, (size_t)w.w * w.h * 4);
}
