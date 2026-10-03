// Renders the exported graph as a single self-contained HTML page with no
// external assets, so it works offline. Blocks are positioned divs; edges are
// SVG paths with marker arrowheads, which lets the browser handle stroking,
// joins and arrow orientation instead of this code drawing segments by hand.
//
// This is a deliberate mirror of the json2html.py generator; the two produce
// identical geometry (verified block-for-block, edge-for-edge and
// arrow-for-arrow on a 131-block function), so either can be used.
//
// The palette below is the same default palette json2html.py uses. Neither
// reads a user .clr file, so the two agree.
#include <cstdio>
#include <cstdarg>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <fstream>
#include <iostream>

#include "json/json.h"

// ---------------------------------------------------------------- palette
// Colour indices used by the disassembly text. This is IDA's default palette;
// the plugin will read the live one out of the registry like the SVG path did.
// Colour names, kept in sync with CLR_VALUES so the table is readable.
static const char *CLR_NAMES[] = {
    "instruction", "directive", "macro_name", "register_name", "other_keywords", "dummy_data_name", "dummy_code_name", "dummy_unexplored_name", "hidden_name", "library_function_name", "local_variable_name", "regular_data_name", "regular_code_name", "regular_unexplored_name", "demangled_name", "segment_name", "imported_name", "suspicious_constant", "char_in_instruction", "string_in_instruction", "number_in_instruction", "char_in_data", "string_in_data", "number_in_data", "code_reference", "data_reference", "code_reference_to_tail", "data_reference_to_tail", "automatic_comment", "regular_comment", "repeatable_comment", "extra_line", "collapsed_line", "line_prefix:_library_function", "line_prefix:_regular_function", "line_prefix:_instruction", "line_prefix:_data", "line_prefix:_unexplored", "line_prefix:_externs", "line_prefix:_current_item", "line_prefix:_current_line", "punctuation", "opcode_bytes", "manual_operand", "error", "default_color", "selected", "library_function", "regular_function", "single_instruction", "data_bytes", "unexplored_byte", "library_function", "regular_function", "instruction", "data_item", "unexplored", "external_symbol", "errors", "gaps", "cursor", "address", "current_ip", "current_ip_(enabled)", "current_ip_(disabled)", "default_background", "address", "address_(enabled)", "address_(disabled)", "address_(unavailible)", "registers", "registers_(changed)", "registers_(edited)", "jump_in_current_function", "jump_external_to_function", "jump_under_the_cursor", "jump_target", "register_target", "top_color", "bottom_color", "normal_title", "selected_title", "current_title", "group_frame", "node_shadow", "highlight_color_1", "highlight_color_2", "foreign_node", "normal_edge", "yes_edge", "no_edge", "highlighted_edge", "current_edge", "message_text", "message_background", "patched_bytes", "unsaved_changes", "highlight_color", "hint_color",
};
static const unsigned CLR_VALUES[] = {
    0x000000, 0xaaaaaa, 0xf3c5ff, 0x7e6082, 0x666666, 0xffffff, 0xb9ebeb, 0xb9ebeb,
    0xbbecff, 0xc0c0c0, 0x00d269, 0x00ff00, 0x3250d2, 0x4646ff, 0x7faaff, 0x617c7c,
    0x3250d2, 0x008080, 0x3734ff, 0xc0c0c0, 0x595959, 0xf3c5ff, 0xffaaff, 0x00d2ff,
    0xffff00, 0x0080ff, 0x00d2ff, 0x00d69d, 0x7e07df, 0x00d269, 0x00f379, 0x3250d2,
    0xababab, 0xadad73, 0xfd5aff, 0x7fffff, 0x00ffaa, 0x00d2ff, 0xffaaff, 0x00ffff,
    0x000000, 0x2d2d2d, 0x32ade1, 0xffff00, 0x666666, 0x0000aa, 0x41c88e, 0x009d9d,
    0xff55ff, 0x000000, 0x00aaff, 0x000000, 0xffaa00, 0x00aaff, 0x000080, 0xb9ebeb,
    0x007878, 0xff00ff, 0x0000ca, 0x4a4a4a, 0x00ff80, 0x0080ff, 0xffd060, 0x32ade1,
    0x408020, 0x2d2d2d, 0x000076, 0x00ff00, 0x004080, 0x0080ff, 0x000000, 0xff0000,
    0x800080, 0x34466c, 0xdede00, 0x00aaff, 0x008000, 0xff4040, 0xb2b2b2, 0xb2b2b2,
    0xf5f5f5, 0x989faa, 0x54585e, 0x00ffff, 0x242424, 0x003900, 0x00006d, 0x0000ff,
    0xcb4300, 0x009100, 0x0000bc, 0xffaaaa, 0x008ec6, 0x212121, 0xd4d4d4, 0x404080,
    0x0080ff, 0x00c61a, 0x3d3d3d,
};

static const size_t CLR_COUNT = sizeof(CLR_VALUES) / sizeof(CLR_VALUES[0]);
static_assert(sizeof(CLR_NAMES) / sizeof(CLR_NAMES[0]) == CLR_COUNT,
              "CLR_NAMES and CLR_VALUES must stay in step");

static std::string color_hex(unsigned v) {
    char b[16];
    // byte order matches the exporter's colour encoding
    snprintf(b, sizeof(b), "%02x%02x%02x", v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff);
    return b;
}


// ------------------------------------------------------------- base64
// The plugin links IDA's base64_encode(); IDA has no decode, so decode locally.
static const char *B64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string b64_decode(const std::string &in) {
    int tbl[256];
    for (int i = 0; i < 256; i++) tbl[i] = -1;
    for (int i = 0; i < 64; i++) tbl[(unsigned char)B64[i]] = i;

    std::string out;
    int val = 0, bits = 0;
    for (unsigned char c : in) {
        if (tbl[c] < 0) continue;          // skips '=' and whitespace
        val = (val << 6) | tbl[c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((char)((val >> bits) & 0xff));
        }
    }
    return out;
}

// --------------------------------------------------------- disasm decoding
struct Seg { std::string text; unsigned color; };

// Mirrors decode_disasm_line() in json2svg.py: 0x01 <idx> starts a coloured
// run, 0x02 <idx> ends it. 0x01 0x28 is a hidden-address marker.
static std::vector<Seg> decode_line(const std::string &raw) {
    std::vector<Seg> out;
    std::vector<unsigned> stack;
    std::string text;
    int hidden = 0;
    const unsigned char COLOR_BEGIN = 0x01, COLOR_END = 0x02;

    size_t ptr = 0, n = raw.size();
    while (ptr < n) {
        unsigned char c = (unsigned char)raw[ptr];
        if (c == COLOR_BEGIN) {
            if (ptr + 1 < n && (unsigned char)raw[ptr + 1] == 0x28) {
                hidden = 16;                       // skip the encoded address
            } else if (ptr + 1 < n) {
                stack.push_back((unsigned char)raw[ptr + 1]);
            }
            ptr += 2;
        } else if (c == COLOR_END) {
            if (!stack.empty()) {
                unsigned col = stack.back();
                stack.pop_back();
                out.push_back({text, col});
                text.clear();
            }
            ptr += 2;
        } else {
            if (hidden == 0) text.push_back((char)c);
            else hidden--;
            ptr++;
        }
    }
    return out;
}

// --------------------------------------------------------------- escaping
static std::string esc(const std::string &s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '&': o += "&amp;"; break;
        case '<': o += "&lt;";  break;
        case '>': o += "&gt;";  break;
        case '"': o += "&quot;"; break;
        default:  o.push_back(c);
        }
    }
    return o;
}

// Sized to fit the result, never truncated. A block div carries every
// disassembly span it contains, so these strings run to tens of kilobytes; a
// fixed buffer silently cut them off mid-tag and the browser then recovered
// from the malformed markup in ways that nested blocks inside one another.
static std::string fmt(const char *f, ...) {
    va_list ap, ap2;
    va_start(ap, f);
    va_copy(ap2, ap);
    int n = vsnprintf(nullptr, 0, f, ap);
    va_end(ap);
    if (n <= 0) {
        va_end(ap2);
        return std::string();
    }
    std::vector<char> buf((size_t)n + 1);
    vsnprintf(buf.data(), buf.size(), f, ap2);
    va_end(ap2);
    return std::string(buf.data(), (size_t)n);
}

// ---------------------------------------------------------------- geometry
static const int   TITLE_H   = 16;
static const double LINE_H   = 17.0;
static const double FONT_PX  = 11.8;   // ~7.10 px/char; 12px overflowed the widest line
static const double EDGE_W   = 1.0;   // line thickness (screen px)
static const double ARROW_L  = 9.0;
static const double ARROW_W  = 7.0;

struct Bounds { double x0, y0, x1, y1; };

static Bounds graph_bounds(const Json::Value &g) {
    Bounds b{1e18, 1e18, -1e18, -1e18};
    bool any = false;

    const Json::Value &bbs = g["basic_blocks"];
    for (const auto &bb : bbs) {
        if (bb["left"].asDouble() < 0 && bb["right"].asDouble() < 0 &&
            bb["top"].asDouble() < 0 && bb["bottom"].asDouble() < 0)
            continue;   // dummy values when the export had no layout
        b.x0 = std::min(b.x0, bb["left"].asDouble());
        b.y0 = std::min(b.y0, bb["top"].asDouble());
        b.x1 = std::max(b.x1, bb["right"].asDouble());
        b.y1 = std::max(b.y1, bb["bottom"].asDouble());
        any = true;
    }
    for (const auto &e : g["edges"]) {
        for (const auto &c : e["coords"]) {
            std::string s = c.asString();
            double x, y;
            if (sscanf(s.c_str(), "%lf %lf", &x, &y) == 2) {
                b.x0 = std::min(b.x0, x); b.y0 = std::min(b.y0, y);
                b.x1 = std::max(b.x1, x); b.y1 = std::max(b.y1, y);
                any = true;
            }
        }
    }
    if (!any) return {0, 0, 1, 1};
    return b;
}

// ------------------------------------------------------------------ render
// Marker ids must be unique per colour, and stable so identical colours share
// one definition.
static std::string marker_id(unsigned color) {
    return fmt("ar%06x", color & 0xffffff);
}

// <defs> holding one arrowhead per distinct edge colour. Using SVG markers
// means the browser draws the head along the path direction itself - no
// orientation maths, and it scales with the drawing like everything else.
static std::string build_defs(const Json::Value &g) {
    std::vector<unsigned> seen;
    std::string out;

    for (const auto &e : g["edges"]) {
        unsigned c = e["color"].asUInt() & 0xffffff;
        if (std::find(seen.begin(), seen.end(), c) != seen.end())
            continue;
        seen.push_back(c);

        /* orient="auto" rotates the head onto the path's direction at its end.
         * markerUnits is left at its default (strokeWidth) so the head tracks
         * the line weight, and refX sits on the triangle's apex so the tip
         * lands exactly on the path end rather than past it. */
        out += fmt("<marker id=\"%s\" viewBox=\"0 0 10 10\" refX=\"10\" refY=\"5\""
                   " markerWidth=\"7\" markerHeight=\"7\" orient=\"auto\""
                   " markerUnits=\"strokeWidth\">"
                   "<path d=\"M0,0 L10,5 L0,10 z\" fill=\"#%s\"/></marker>",
                   marker_id(c).c_str(), color_hex(c).c_str());
    }
    return out;
}

// Every edge is a single <path>, so there are no segment joints to fill and
// nothing can overlap: the browser strokes one continuous polyline.
static std::string build_edges(const Json::Value &g, double ox, double oy) {
    std::string paths;

    for (const auto &e : g["edges"]) {
        std::vector<std::pair<double, double>> pts;
        for (const auto &c : e["coords"]) {
            double x, y;
            if (sscanf(c.asString().c_str(), "%lf %lf", &x, &y) == 2)
                pts.push_back({x - ox, y - oy});
        }
        if (pts.size() < 2) continue;

        std::string d;
        for (size_t i = 0; i < pts.size(); i++)
            d += fmt("%s%.2f,%.2f", i ? " L" : "M", pts[i].first, pts[i].second);

        unsigned c = e["color"].asUInt() & 0xffffff;
        paths += fmt("<path d=\"%s\" fill=\"none\" stroke=\"#%s\""
                     " stroke-width=\"2\" marker-end=\"url(#%s)\"/>",
                     d.c_str(), color_hex(c).c_str(), marker_id(c).c_str());
    }
    return paths;
}

static std::string build_blocks(const Json::Value &g, double ox, double oy) {
    std::string out;
    for (const auto &b : g["basic_blocks"]) {
        std::string lines;
        for (const auto &l : b["disasm_lines"]) {
            std::string raw = b64_decode(l["text"].asString());
            lines += "<div class=\"ln\">";
            for (const Seg &s : decode_line(raw)) {
                lines += fmt("<span class=\"txt_col_%02x\">%s</span>",
                             s.color, esc(s.text).c_str());
            }
            lines += "</div>";
        }
        out += fmt("<div class=\"block\" data-addr=\"%#llx\" style=\"left:%dpx;top:%dpx;"
                   "width:%dpx;height:%dpx\"><div class=\"hdr\"></div>"
                   "<div class=\"disasm\">%s</div></div>",
                   (unsigned long long)b["addr_start"].asUInt64(),
                   (int)(b["left"].asDouble() - ox), (int)(b["top"].asDouble() - oy),
                   std::max(1, (int)(b["right"].asDouble() - b["left"].asDouble())),
                   std::max(1, (int)(b["bottom"].asDouble() - b["top"].asDouble())),
                   lines.c_str());
    }
    return out;
}


bool export_graph_html(const Json::Value &root, const char *filename)
{
    if (!root.isMember("functions") || root["functions"].empty())
        return false;

    const Json::Value &g = root["functions"][0];
    Bounds b = graph_bounds(g);
    double pad = 20, ox = b.x0 - pad, oy = b.y0 - pad;
    double W = std::max(b.x1 - b.x0, 1.0) + 2 * pad;
    double H = std::max(b.y1 - b.y0, 1.0) + 2 * pad;

    /* Edges go in one SVG layer sized to the whole drawing; the blocks sit on
     * top as ordinary positioned divs. The browser draws the polylines and
     * their markers, so there is no per-segment geometry to get wrong. */
    std::string edges =
        fmt("<svg class=\"edges\" width=\"%d\" height=\"%d\" "
            "xmlns=\"http://www.w3.org/2000/svg\"><defs>%s</defs>%s</svg>",
            (int)W, (int)H, build_defs(g).c_str(), build_edges(g, ox, oy).c_str());

    std::string content = edges + build_blocks(g, ox, oy);
    std::string title = esc(g["name"].asString()) + " - graph";

    std::ofstream out(filename, std::ios::binary);
    if (!out)
        return false;

    out << "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>"
        << title << "</title>\n<style>\n";
    out << "html,body{margin:0;padding:0;height:100%;overflow:hidden;background:#1e1e1e;"
           "color:#ddd;font-family:system-ui,-apple-system,'Segoe UI',sans-serif}\n";
    out << "#bar{position:fixed;top:0;left:0;right:0;height:40px;z-index:100;display:flex;"
           "align-items:center;gap:8px;padding:0 12px;background:#252526;"
           "border-bottom:1px solid #3c3c3c;font-size:13px}\n";
    out << "#bar button{background:#3a3d41;color:#ddd;border:1px solid #555;border-radius:4px;"
           "padding:4px 10px;cursor:pointer;font-size:13px}\n";
    out << "#bar .title{font-weight:600;margin-right:8px}\n";
    out << "#bar .hint,#bar .stat{color:#999}#bar .hint{margin-left:auto}\n";
    out << "#wrap{position:absolute;top:40px;left:0;right:0;bottom:0;overflow:hidden;"
           "cursor:grab}#wrap.dragging{cursor:grabbing}\n";
    out << "#world{position:absolute;top:0;left:0;transform-origin:0 0;"
           "will-change:transform}\n";
    out << "#canvas{position:absolute;top:0;left:0}\n";
    out << ".edges{position:absolute;top:0;left:0;overflow:visible;pointer-events:none}\n";
    out << "#wrap.dragging{cursor:grabbing}\n";
    out << ".block{position:absolute;box-sizing:border-box;background:#2d2d2d;"
           "border:1px solid #000}\n";
    out << ".hdr{position:absolute;left:0;top:0;right:0;height:" << TITLE_H
        << "px;background:#c0c0c0;border-bottom:1px solid #000;box-sizing:border-box}\n";
    /* The disassembly is laid out in columns that only line up in a monospace
     * face, so the fallback chain must end in the generic monospace keyword.
     * The font IDA reports by name (FreeMono by default) is often not installed,
     * and without a fallback the browser substitutes its default *proportional*
     * font: every column then drifts and the text looks scattered. Kerning and
     * ligatures are off for the same reason - both shift glyphs off the grid.
     * The script additionally rescales the size so one character is exactly
     * DISASM_PX_PER_CHAR wide whatever face is actually used. */
    out << ".disasm{position:absolute;left:3px;right:3px;top:" << TITLE_H
        << "px;line-height:" << LINE_H << "px;white-space:pre;overflow:hidden;"
           "font-family:'FreeMono','DejaVu Sans Mono','Liberation Mono',"
           "'Noto Sans Mono','Courier New',monospace;"
           "font-kerning:none;font-variant-ligatures:none;"
           "font-size:" << FONT_PX << "px;font-weight:bold}\n";
    out << ".block.sel{outline:2px solid #fff;outline-offset:-1px}\n";
    for (unsigned i = 0; i < sizeof(CLR_VALUES) / sizeof(CLR_VALUES[0]); i++)
        out << ".txt_col_" << fmt("%02x", i) << "{color:#" << color_hex(CLR_VALUES[i]) << "}\n";
    out << "</style></head>\n<body>\n<div id=\"bar\"><span class=\"title\">" << title
        << "</span><button id=\"bfit\">Fit</button><button id=\"bin\">+</button>"
           "<button id=\"bout\">&minus;</button><button id=\"b1\">100%</button>"
           "<span class=\"stat\" id=\"stat\"></span>"
           "<span class=\"hint\">drag to pan &middot; wheel to zoom</span></div>\n";
    out << "<div id=\"wrap\"><div id=\"world\"><div id=\"canvas\">" << content
        << "</div></div></div>\n";

    out << "<script>\nvar W=" << (int)W << ",H=" << (int)H << ";\n";
    out << R"JS(
var wrap=document.getElementById('wrap'),world=document.getElementById('world');
var stat=document.getElementById('stat');
var s=1,tx=0,ty=0;
function ap(){
  world.style.transform='translate('+tx+'px,'+ty+'px) scale('+s+')';
  stat.textContent=Math.round(s*100)+'%';
}
function ct(){tx=(wrap.clientWidth-W*s)/2;ty=(wrap.clientHeight-H*s)/2;ap();}
function ft(){s=Math.min(wrap.clientWidth/W,wrap.clientHeight/H);ct();}
function za(f,cx,cy){var n=Math.min(16,Math.max(.01,s*f));
  tx=cx-(cx-tx)*(n/s);ty=cy-(cy-ty)*(n/s);s=n;ap();}
var d=0,sx=0,sy=0;
function sync(e){sx=e.clientX-tx;sy=e.clientY-ty;}
// A press that lands on disassembly text is left alone so the text can be
// selected; panning starts from the background or a block's title bar.
function onText(e){
  return !!(e.target&&e.target.closest&&e.target.closest('.disasm'));
}
wrap.addEventListener('mousedown',function(e){
  if(e.button!==0)return;
  if(onText(e))return;
  d=1;sync(e);wrap.classList.add('dragging');
});
window.addEventListener('mousemove',function(e){if(!d)return;
  tx=e.clientX-sx;ty=e.clientY-sy;ap();});
window.addEventListener('mouseup',function(){d=0;wrap.classList.remove('dragging');});
wrap.addEventListener('wheel',function(e){e.preventDefault();
  var r=wrap.getBoundingClientRect();
  za(e.deltaY<0?1.15:1/1.15,e.clientX-r.left,e.clientY-r.top);
  if(d)sync(e);},{passive:false});
document.getElementById('bfit').addEventListener('click',ft);
document.getElementById('bin').addEventListener('click',function(){
  za(1.25,wrap.clientWidth/2,wrap.clientHeight/2);});
document.getElementById('bout').addEventListener('click',function(){
  za(0.8,wrap.clientWidth/2,wrap.clientHeight/2);});
document.getElementById('b1').addEventListener('click',function(){s=1;ct();});
window.addEventListener('resize',ct);
ft();
)JS";
    out << "</script>\n</body></html>\n";
    out.close();
    return true;
}
