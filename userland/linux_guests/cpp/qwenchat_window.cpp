/* qwenchat: the conversation in a window on the NONOS desktop. */
#include "qwenchat.h"
#include "qwenchat_metrics.h"
#include "qwenchat_smaller.h"
#include "qwenui.h"

#include <cerrno>
#include <unistd.h>

/* Room for the conversation, and for the desktop beside it on a 1280x720 screen. */
static const int WIDTH = 880, HEIGHT = 560;

static bool escaped(const std::vector<Key> &keys) {
    for (Key k : keys)
        if (k.code == 0x1B) return true;
    return false;
}

int chat_window(const ChatArgs &a) {
    Wl w;
    if (!wl_open(w, WIDTH, HEIGHT, "Qwen - local AI on NONOS")) return 1;
    View v;
    /* The tier by its label, as setup and the Store name it; a file no tier names, by its name. */
    std::string label, word;
    if (!model_tier(a.model, label, word)) label = a.model.substr(a.model.rfind('/') + 1);
    v.title = label + "  |  offline";
    v.status = "loading the model";
    std::vector<Key> keys;
    for (int i = 0; i < 100 && !w.configured; i++) wl_poll(w, keys), usleep(20000);
    ui_draw(w, v), wl_present(w);
    Chat c;
    Busy busy = {&w, &v, &c};
    busy.since = busy_now();
    c.stop = busy_stop, c.stop_to = &busy;
    c.step = window_importing, c.step_to = &busy;
    v.said.push_back({false, WINDOW_FIRST_USE});
    const double began = metrics_now();
    const bool opened = chat_open(a, c);
    metrics_load(c, opened, metrics_now() - began);
    v.said.clear();
    if (!opened) {
        /* Closed or Esc while it loaded: the person changed their mind. */
        if (c.err == ECANCELED) return ui_wipe(w, v), wl_close(w), 0;
        /* No model yet: one line, and what to do; any other refusal in full. */
        const bool missing = c.err == ENOENT && !word.empty();
        const std::string why = missing ? no_model_yet(label, word) : chat_failure(a, c) + offer_smaller(a, c, true);
        v.said.push_back({false, why});
        v.status = window_not_opened(c.err);
        ui_draw(w, v), wl_present(w);
        for (keys.clear(); wl_poll(w, keys) && !escaped(keys); usleep(50000)) {
            for (Key k : keys)
                if (ui_scroll_key(w, v, k)) ui_draw(w, v), wl_present(w);
            keys.clear(), ui_redraw_resized(w, v);
        }
        ui_wipe(w, v), wl_close(w);
        return c.err == ENOMEM ? 4 : 1;
    }
    v.status = c.mem.free < 0 ? "ready, free memory unknown" : "ready";
    v.thinks = c.can_think;
    ui_draw(w, v), wl_present(w);
    bool open = true;
    for (bool shown = w.configured; open && wl_poll(w, keys);) {
        if (!shown && w.configured) shown = true, ui_draw(w, v), wl_present(w);
        ui_redraw_resized(w, v);
        if (keys.empty()) { usleep(15000); continue; }
        for (Key k : keys) open = open && window_key(a, c, w, v, k);
        keys.clear();
        ui_draw(w, v), wl_present(w);
    }
    ui_wipe(w, v), wl_close(w), chat_close(c);
    return 0;
}
