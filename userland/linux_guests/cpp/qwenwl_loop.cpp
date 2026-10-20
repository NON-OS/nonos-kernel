/* qwenwl: staying up, taking keys, and showing each frame. */
#include "qwenwl.h"
#include "qwenwl_ids.h"

#include <sys/mman.h>
#include <unistd.h>

/*
 * xdg_wm_base.ping, xdg_toplevel.configure, xdg_surface.configure,
 * xdg_toplevel.close, key, wheel (a vertical wl_pointer.axis). A configure's
 * size (F11 or the window made full screen, and back) is taken before its
 * ack, so the next present is the frame drawn at that size; 0 by 0 is the
 * size the window opened at.
 */
bool wl_poll(Wl &w, std::vector<Key> &keys) {
    uint32_t object;
    uint16_t op;
    std::vector<uint8_t> body;
    while (!w.closed && wl_event(w, object, op, body)) {
        if (object == XDG && op == 0) {
            Req pong(XDG, 3);
            wl_send(w, pong.u32(wl_word(body, 0)));
        } else if (object == TOP && op == 0) {
            w.want_w = (int)wl_word(body, 0), w.want_h = (int)wl_word(body, 4);
        } else if (object == XSURF && op == 0) {
            const bool own = w.want_w <= 0 || w.want_h <= 0;
            if (w.configured) wl_resize(w, own ? w.own_w : w.want_w, own ? w.own_h : w.want_h);
            Req ack(XSURF, 4);
            wl_send(w, ack.u32(wl_word(body, 0)));
            w.configured = true;
        } else if (object == TOP && op == 1) {
            w.closed = true;
        } else if (object == KBD && op == 3 && wl_word(body, 12) == 1) {
            keys.push_back(Key{wl_word(body, 8)});
        } else if (object == PTR && op == 4 && wl_word(body, 4) == 0 && wl_word(body, 8) != 0) {
            const int32_t value = (int32_t)wl_word(body, 8), notches = value / (10 << 8);
            keys.push_back(Key{0, notches ? notches : (value > 0) - (value < 0)});
        }
    }
    return !w.closed;
}

void wl_present(Wl &w) {
    if (!w.configured) return;
    Req attach(SURF, 1), damage(SURF, 2), commit(SURF, 6);
    wl_send(w, attach.u32(w.buf).u32(0).u32(0));
    wl_send(w, damage.u32(0).u32(0).u32(w.w).u32(w.h));
    wl_send(w, commit);
}

void wl_close(Wl &w) {
    if (w.fd < 0) return;
    if (w.configured) {
        Req attach(SURF, 1), commit(SURF, 6);
        wl_send(w, attach.u32(0).u32(0).u32(0)), wl_send(w, commit);
    }
    Req top(TOP, 0), xsurf(XSURF, 0), surf(SURF, 0), buf(w.buf, 0), pool(w.pool, 1);
    wl_send(w, top), wl_send(w, xsurf), wl_send(w, surf), wl_send(w, buf), wl_send(w, pool);
    close(w.fd), w.fd = -1;
    if (w.memfd >= 0) close(w.memfd), w.memfd = -1;
    if (w.px) munmap(w.px, (size_t)w.w * w.h * 4), w.px = nullptr;
}
