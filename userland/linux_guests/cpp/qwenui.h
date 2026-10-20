/* qwenui: what qwenchat's window shows, drawn into its buffer. */
#pragma once
#include <string>
#include <utility>
#include <vector>

#include "qwenwl.h"

struct Said {
    bool user;
    std::string text;
};

struct View {
    std::string title;  /* the model, in the header */
    std::vector<Said> said;
    std::string input;
    std::string status; /* right of the header: loading, thinking, speed */
    bool thinks = false; /* the model can think aloud: /think and /nothink */
    size_t back = 0;     /* lines scrolled up from the newest; 0 follows the conversation */
};

/* NONOS key codes the bridge forwards unchanged; hand-synced with
 * userland/app_skeleton/src/input/keys.rs. */
static const uint32_t KEY_UP = 0x1201, KEY_DOWN = 0x1202, KEY_HOME = 0x1205, KEY_END = 0x1206;
static const uint32_t KEY_PAGE_UP = 0x1207, KEY_PAGE_DOWN = 0x1208;

void ui_draw(Wl &w, const View &v);
/* The conversation as drawn lines, each with its colour, oldest first. */
std::vector<std::pair<std::string, uint32_t>> ui_lines(const Wl &w, const View &v);
/* How many lines the conversation area holds; 0 for a window too small. */
size_t ui_fit(const Wl &w);
/* The first line shown: `back` lines up from the newest, held in range. */
size_t ui_from(size_t lines, size_t fit, size_t back);
/* Up, Down, Page Up/Down, Home, End and the wheel move `back`; false for any other key. */
bool ui_scroll_key(const Wl &w, View &v, Key k);
/* Drawn again and shown when the window took a new size (wl_resize). */
void ui_redraw_resized(Wl &w, const View &v);
/* Text in the atlas's cells at (x, y), clipped to the buffer. */
void ui_text(Wl &w, int x, int y, const std::string &s, uint32_t color);
void ui_fill(Wl &w, int x, int y, int width, int height, uint32_t color);
/* `s` broken into lines of at most `cols` cells, at spaces where it can. */
std::vector<std::string> ui_wrap(const std::string &s, size_t cols);
/* Wipe what was said, the draft and the pixels that showed them. */
void ui_wipe(Wl &w, View &v);

struct ChatArgs;
struct Chat;
/* One key in the chat window; false once the person asks to close it. */
bool window_key(const ChatArgs &a, Chat &c, Wl &w, View &v, Key k);

/*
 * The window while the model loads or a turn computes: the compositor is
 * answered, the status shows how far along and for how long, and Esc or
 * the window's close stops the work.
 */
struct Busy {
    Wl *w;
    View *v;
    Chat *c;
    const char *doing = "loading the model";
    double since = 0, shown = 0;
    bool quit = false; /* the window was closed, not only the work stopped */
};
/* Chat::stop for the window: true once Esc is pressed or the window closed. */
bool busy_stop(void *to);
double busy_now();

/*
 * While the model opens (qwenchat_window_open.cpp): Chat::step for the
 * window, the note shown meanwhile, and the status when it did not open.
 */
void window_importing(void *to, int part, int parts, long long bytes);
extern const char *const WINDOW_FIRST_USE;
const char *window_not_opened(int err);
