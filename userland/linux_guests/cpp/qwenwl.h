/*
 * qwenwl: the few Wayland requests qwenchat's window needs, spoken on the
 * wire with no library: a toplevel, one shared-memory buffer it paints
 * into, and the keyboard. The personality's display server answers them;
 * it copies the buffer on every commit, so one buffer is enough.
 */
#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct Wl {
    int fd = -1;
    std::vector<uint8_t> rx;
    uint32_t *px = nullptr;
    int w = 0, h = 0;
    bool closed = false;
    bool configured = false;
    /* The pool and buffer the pixels are in now, and the memfd behind them. */
    uint32_t pool = 0, buf = 0;
    int memfd = -1;
    /* The size the window opened at, taken back on a configure of 0 by 0. */
    int own_w = 0, own_h = 0;
    /* The size the last toplevel configure named, taken when it is acked. */
    int want_w = 0, want_h = 0;
    /* Pixels at a new size, not drawn yet: the caller draws and presents. */
    bool resized = false;
};

/* One request under construction: object, opcode, then arguments. */
struct Req {
    std::vector<uint8_t> b;
    uint16_t op;
    Req(uint32_t object, uint16_t opcode);
    Req &u32(uint32_t v);
    Req &str(const std::string &s);
};

/* A key the user pressed: a NONOS key code, which for text is the character. */
struct Key {
    uint32_t code;
    int32_t wheel = 0; /* Wheel notches, Wayland sign: positive toward the newest. */
};

bool wl_send(Wl &w, Req &r);
bool wl_send_fd(Wl &w, Req &r, int fd);
/* The next whole event, or false when none is queued (or the socket died). */
bool wl_event(Wl &w, uint32_t &object, uint16_t &op, std::vector<uint8_t> &body);
uint32_t wl_word(const std::vector<uint8_t> &body, size_t at);

bool wl_open(Wl &w, int width, int height, const char *title);
/* A pool and buffer of `width` by `height` under ids `pool` and `buf`. */
bool wl_buffer(Wl &w, int width, int height, uint32_t pool, uint32_t buf, uint32_t *&px, int &memfd);
/*
 * The pixels moved to a buffer of `width` by `height` (the other id pair),
 * the old pair destroyed, and `resized` set. False, keeping the old buffer,
 * when there is no memory for the new one.
 */
bool wl_resize(Wl &w, int width, int height);
/* Answer pings and configures; append keys pressed. False once closed. */
bool wl_poll(Wl &w, std::vector<Key> &keys);
void wl_present(Wl &w);
/*
 * Take the window down in order: the surface unmapped (a null buffer
 * committed), then the toplevel, its xdg surface and the surface destroyed,
 * then the buffer and its pool, and only then the connection closed and the
 * pixels unmapped. Nothing the compositor holds outlives what it refers to.
 */
void wl_close(Wl &w);
