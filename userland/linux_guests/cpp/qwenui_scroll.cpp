/* qwenui: how far up the conversation is scrolled. */
#include "qwenui.h"

#include <algorithm>

/* Lines per wheel notch, as app_skeleton scroll::WHEEL_LINES. */
static const size_t WHEEL_LINES = 3;

size_t ui_from(size_t lines, size_t fit, size_t back) {
    const size_t max = lines > fit ? lines - fit : 0;
    return max - std::min(back, max);
}

bool ui_scroll_key(const Wl &w, View &v, Key k) {
    const size_t lines = ui_lines(w, v).size(), fit = ui_fit(w);
    const size_t max = lines > fit ? lines - fit : 0, page = fit > 1 ? fit - 1 : 1;
    if (k.wheel > 0) v.back -= std::min(v.back, (size_t)k.wheel * WHEEL_LINES);
    else if (k.wheel < 0) v.back += (size_t)-(int64_t)k.wheel * WHEEL_LINES;
    else if (k.code == KEY_UP) v.back += 1;
    else if (k.code == KEY_DOWN) v.back -= std::min<size_t>(v.back, 1);
    else if (k.code == KEY_PAGE_UP) v.back += page;
    else if (k.code == KEY_PAGE_DOWN) v.back -= std::min(v.back, page);
    else if (k.code == KEY_HOME) v.back = max;
    else if (k.code == KEY_END) v.back = 0;
    else return false;
    v.back = std::min(v.back, max);
    return true;
}
