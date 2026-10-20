/* qwenchat: the window kept alive while the model loads or answers. */
#include "qwenchat.h"
#include "qwenui.h"

#include <chrono>
#include <cstdio>

double busy_now() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

static bool scrolled(Busy &b, const std::vector<Key> &keys) {
    bool moved = false;
    for (Key k : keys) moved = ui_scroll_key(*b.w, *b.v, k) || moved;
    return moved;
}

bool busy_stop(void *to) {
    Busy &b = *(Busy *)to;
    std::vector<Key> keys;
    if (!wl_poll(*b.w, keys)) return b.quit = true;
    ui_redraw_resized(*b.w, *b.v);
    for (Key k : keys)
        if (k.code == 0x1B) return true;
    /* Scroll keys move the view; other keys wait for the answer: typing ahead is not kept. */
    if (scrolled(b, keys)) ui_draw(*b.w, *b.v), wl_present(*b.w);
    const double t = busy_now();
    if (t - b.shown < 1.0) return false;
    b.shown = t;
    const int s = (int)(t - b.since);
    char line[96];
    if (b.c->model)
        snprintf(line, sizeof line, "%s, %d:%02d, Esc stops", b.doing, s / 60, s % 60);
    else
        snprintf(line, sizeof line, "%s %d%%, Esc stops", b.doing, (int)(b.c->loaded * 100));
    b.v->status = line;
    ui_draw(*b.w, *b.v), wl_present(*b.w);
    return false;
}
