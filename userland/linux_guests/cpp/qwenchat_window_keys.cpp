/* qwenchat: what a key does in the chat window. */
#include "qwenchat.h"
#include "qwenchat_metrics.h"
#include "qwenui.h"

#include <cstdio>

/* Each piece is shown at once, thinking aloud never. Keys and pings are
 * answered by busy_stop, which the compute asks while it runs. */
static void to_window(void *to, const char *piece, size_t n, bool thought) {
    Busy *b = (Busy *)to;
    const size_t before = b->v->back ? ui_lines(*b->w, *b->v).size() : 0;
    if (!thought) b->v->said.back().text.append(piece, n);
    const size_t after = b->v->back ? ui_lines(*b->w, *b->v).size() : 0;
    if (after > before) b->v->back += after - before;
    ui_draw(*b->w, *b->v), wl_present(*b->w);
}

static bool answer(const ChatArgs &a, Chat &c, Wl &w, View &v) {
    std::string said = v.input + "\n";
    v.said.push_back({true, v.input}), v.said.push_back({false, ""});
    v.input.clear();
    v.back = 0;
    Busy &b = *(Busy *)c.stop_to;
    b.doing = "answering", b.since = b.shown = busy_now();
    v.status = "answering, Esc stops";
    ui_draw(w, v), wl_present(w);
    int made = 0;
    Timed t = {to_window, &b, metrics_now()};
    bool ok = chat_turn(a, c, said, timed_put, &t, made);
    metrics_turn(c, t, made);
    if (c.stopped) {
        v.said.back().text += v.said.back().text.empty() ? "(stopped)" : " (stopped)";
        v.status = "stopped, this turn is forgotten";
        return ok;
    }
    char line[64];
    snprintf(line, sizeof line, "%d tokens, %.1f tok/s", made, made / (busy_now() - b.since + 1e-9));
    v.status = line;
    return ok;
}

/* The words that end the chat, the same as on a terminal. */
static bool closing(const std::string &s) { return s == "/bye" || s == "/exit"; }

/*
 * /think and /nothink: Qwen3 thinks aloud before it answers, or does not,
 * from the next turn on, as on a terminal. Its thinking is never shown in
 * the window; the answer is. A model that cannot think says so.
 */
static bool thinking_word(Chat &c, View &v) {
    if (v.input != "/think" && v.input != "/nothink") return false;
    c.think = c.can_think && v.input == "/think";
    v.status = !c.can_think ? "this model does not think" : c.think ? "thinks before answering" : "no thinking";
    v.input.clear();
    return true;
}

/* Esc clears the line, and on an empty line closes the window. */
bool window_key(const ChatArgs &a, Chat &c, Wl &w, View &v, Key k) {
    if (ui_scroll_key(w, v, k)) return !((Busy *)c.stop_to)->quit;
    if (k.code == 0x0D && closing(v.input)) return false;
    if (k.code == 0x1B && v.input.empty()) return false;
    if (k.code == 0x0D && thinking_word(c, v)) return true;
    if (k.code == 0x0D && v.input == "/reset") chat_reset(c), ui_wipe(w, v), v.status = "forgotten";
    else if (k.code == 0x0D && !v.input.empty() && !answer(a, c, w, v)) v.status = "fault";
    else if (k.code == 0x08 && !v.input.empty()) v.input.pop_back();
    else if (k.code == 0x1B) v.input.clear();
    else if (k.code >= 0x20 && k.code < 0x7F && v.input.size() < 2000) v.input += (char)k.code;
    /* The window closed while it answered. */
    return !((Busy *)c.stop_to)->quit;
}
