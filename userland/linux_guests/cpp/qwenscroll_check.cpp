/*
 * qwenscroll_check: a host check that qwenchat's conversation scrolls: ui_from
 * holds `back` in range, the scroll keys and the wheel move it and nothing else
 * does, and a vertical wl_pointer.axis from a socketpair standing in for the
 * display becomes a wheel Key while the pointer's other events give none. Run by
 * `make nonos-mk-qwenscroll-check NONOS_LINUX_GUESTS=1 NONOS_QWEN=1` (QwenChat.mk);
 * exits 0 when every check holds, else names each that does not.
 */
#include "qwenui.h"
#include "qwenwl_ids.h"

#include <cstdio>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

static int bad = 0;
static void expect(bool ok, const char *what) {
    if (!ok) printf("qwenscroll_check: %s\n", what), bad = 1;
}

/* The keys wl_poll makes of one event from the display's side: object, opcode, words. */
static std::vector<Key> heard(Wl &w, int display, uint32_t object, uint16_t op, std::vector<uint32_t> words) {
    std::vector<uint32_t> m = {object, (uint32_t)((8 + words.size() * 4) << 16) | op};
    m.insert(m.end(), words.begin(), words.end());
    if (write(display, m.data(), m.size() * 4) != (ssize_t)(m.size() * 4)) perror("write");
    std::vector<Key> keys;
    wl_poll(w, keys);
    return keys;
}
static bool one(const std::vector<Key> &k, uint32_t code, int32_t wheel) {
    return k.size() == 1 && k[0].code == code && k[0].wheel == wheel;
}

/* `back` after key `k` from `from` is `to`, and the key was taken. */
static bool moves(const Wl &w, View &v, size_t from, Key k, size_t to) {
    v.back = from;
    return ui_scroll_key(w, v, k) && v.back == to;
}

int main() {
    expect(ui_from(5, 19, 0) == 0 && ui_from(19, 19, 7) == 0 && ui_from(0, 19, 0) == 0, "a short chat scrolls");
    expect(ui_from(100, 19, 0) == 81 && ui_from(100, 19, 10) == 71, "back does not count up from the newest");
    expect(ui_from(100, 19, 81) == 0 && ui_from(100, 19, 500) == 0 && ui_from(100, 60, 50) == 0, "past the top");
    expect(ui_from(100, 0, 0) == 100 && ui_from(100, 0, 30) == 70, "no rows does not hold back in range");
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return puts("qwenscroll_check: no socketpair"), 1;
    fcntl(pair[0], F_SETFL, O_NONBLOCK), fcntl(pair[1], F_SETFL, O_NONBLOCK);
    Wl w;
    w.fd = pair[0], w.w = w.own_w = 880, w.h = w.own_h = 560, w.pool = POOL, w.buf = BUF, w.configured = true;
    if (!wl_buffer(w, w.w, w.h, w.pool, w.buf, w.px, w.memfd)) return puts("qwenscroll_check: no buffer"), 1;
    View v;
    for (int i = 0; i < 60; i++) v.said.push_back({i % 2 == 0, "line " + std::to_string(i)});
    const size_t fit = ui_fit(w), max = ui_lines(w, v).size() - fit, page = fit - 1;
    expect(fit > 2 && max > 3 * page, "the conversation does not overflow the window");
    expect(moves(w, v, 0, {KEY_UP}, 1) && moves(w, v, max, {KEY_UP}, max), "Up");
    expect(moves(w, v, 5, {KEY_DOWN}, 4) && moves(w, v, 0, {KEY_DOWN}, 0), "Down");
    expect(moves(w, v, 0, {KEY_PAGE_UP}, page) && moves(w, v, max - 1, {KEY_PAGE_UP}, max), "Page Up");
    expect(moves(w, v, max, {KEY_PAGE_DOWN}, max - page) && moves(w, v, 2, {KEY_PAGE_DOWN}, 0), "Page Down");
    expect(moves(w, v, 0, {KEY_HOME}, max) && moves(w, v, max, {KEY_END}, 0), "Home or End");
    expect(moves(w, v, 10, {0, 1}, 7) && moves(w, v, 4, {0, 2}, 0), "the wheel toward the newest");
    expect(moves(w, v, 0, {0, -1}, 3) && moves(w, v, max - 1, {0, -4}, max), "the wheel toward the oldest");
    for (uint32_t code : {(uint32_t)'a', 0x0Du, 0u})
        expect(!moves(w, v, 5, {code}, 5) && v.back == 5, "a key that does not scroll moved back");
    expect(one(heard(w, pair[1], PTR, 4, {1, 0, 3 * 10 * 256}), 0, 3), "three notches down");
    expect(one(heard(w, pair[1], PTR, 4, {1, 0, (uint32_t)(-2 * 10 * 256)}), 0, -2), "two notches up");
    expect(one(heard(w, pair[1], PTR, 4, {1, 0, 5}), 0, 1), "a sub-notch is not one notch");
    expect(heard(w, pair[1], PTR, 4, {1, 1, 3 * 10 * 256}).empty() && heard(w, pair[1], PTR, 4, {1, 0, 0}).empty(),
           "a horizontal axis or an axis of 0 scrolls");
    expect(heard(w, pair[1], PTR, 0, {1, SURF, 0, 0}).empty() && heard(w, pair[1], PTR, 2, {1, 0, 0}).empty() &&
               heard(w, pair[1], PTR, 3, {1, 1, 0x110, 1}).empty() && heard(w, pair[1], PTR, 5, {}).empty(),
           "a pointer enter, motion, button or frame is a key");
    expect(one(heard(w, pair[1], KBD, 3, {1, 1, 'q', 1}), 'q', 0), "a key press is not a key");
    return bad ? 1 : (puts("qwenscroll_check: ok"), 0);
}
