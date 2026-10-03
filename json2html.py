#!/usr/bin/env python3

##################################################
# !!! Research-grade code. Feel free to fix. !!! #
##################################################

"""Render an exported function graph as a single self-contained HTML page.

Everything is plain HTML and CSS - no SVG, no canvas, no external assets - so
the page works offline and every element is an ordinary DOM node. Basic blocks
are absolutely positioned divs at the coordinates IDA exported; edges are chains
of rotated divs, one per segment of the polyline IDA routed, with a CSS triangle
at the tip for the arrowhead.

The page pans, zooms and selects text without re-laying anything out: the graph
keeps IDA's own geometry.
"""

import sys, json, base64, os, math
from html import escape
DEFAULT_CLR = """
#[DISASM]
#000000	 //
#ff0000	 //Default color
#ff0000	 //Regular comment
#808080	 //Repeatable comment
#808080	 //Automatic comment
#800000	 //Instruction
#800000	 //Dummy Data Name
#ff0000	 //Regular Data Name
#ff0000	 //Demangled Name
#800000	 //Punctuation
#008000	 //Char constant in instruction
#00ff00	 //String constant in instruction
#008000	 //Numeric constant in instruction
#0080ff	 //Void operand
#008000	 //Code reference
#ff8080	 //Data reference
#0000ff	 //Code reference to tail byte
#008080	 //Data reference to tail byte
#010101	 //Error or problem
#c0c0c0	 //Line prefix
#ff0000	 //Binary line prefix bytes
#ff0000	 //Extra line
#ff0000	 //Alternative operand
#808080	 //Hidden name
#ff8080	 //Library function name
#008000	 //Local variable name
#800000	 //Dummy code name
#ff0000	 //Assembler directive
#800080	 //Macro
#008000	 //String constant in data directive
#008000	 //Char constant in data directive
#408000	 //Numeric constant in data directive
#800000	 //Keywords
#800000	 //Register name
#ff00ff	 //Imported name
#008080	 //Segment name
#800000	 //Dummy unknown name
#ff0000	 //Regular code name
#800000	 //Regular unknown name
#ff0000	 //Collapsed line
#000000	 //Max color number
#ffffff	 //Line prefix: library function
#afbbc0	 //Line prefix: regular function
#ffff00	 //Line prefix: instruction
#000000	 //Line prefix: data
#000080	 //Line prefix: unexplored
#808080	 //Line prefix: externs
#008080	 //Line prefix: current item
#ff00ff	 //Line prefix: current line
#000000	 //Punctuation
#ff0000	 //Opcode bytes
#000000	 //Manual operand
#[NAVBAR]
#ffffaa	 //Library function
#e8a200	 //Regular function
#577ab9	 //Instruction
#c0c0c0	 //Data item
#6bb6b6	 //Unexplored
#ffa6ff	 //External symbol
#5b5bff	 //Errors
#000000	 //Gaps
#7fffff	 //Cursor
#00aaff	 //Address
#[DEBUG]
#ffd060	 //Current IP
#ffa0a0	 //Current IP (+ enabled breakpoint)
#408020	 //Current IP (+ disabled breakpoint)
#ffffcc	 //Default background
#0000ff	 //Address (+ enabled breakpoint)
#00ff00	 //Address (+ disabled breakpoint)
#004080	 //Current IP (+ unavailable breakpoint)
#0080ff	 //Address (+ unavailable breakpoint)
#000000	 //Registers
#ff0000	 //Registers (changed)
#800080	 //Registers (edited)
#[ARROW]
#c0c0c0	 //Jump in current function
#0000ff	 //Jump external to function
#000000	 //Jump under the cursor
#008000	 //Jump target
#ff4040	 //Register target
#[GRAPH]
#ffffff	 //Top color
#fff8e0	 //Bottom color
#ffffff	 //Normal title
#f9f9b1	 //Selected title
#cfcfa0	 //Current title
#00ffff	 //Group frame
#000000	 //Node shadow
#ffffcc	 //Highlight color 1
#ccffcc	 //Highlight color 2
#0000ff	 //Foreign node
#ff0000	 //Normal edge
#008000	 //Yes edge
#0000ff	 //No edge
#ff00ff	 //Highlighted edge
#ffff00	 //Current edge
#[MISC]
#000000	 //Message text
#ffffff	 //Message background
#404080	 //Patched bytes
#0080ff	 //Unsaved changes
#[OTHER]
#00ffff	 //Highlight color
#e1ffff	 //Hint color
#[SYNTAX]
#ff0000	0	0	 //Keyword 1
#800080	0	0	 //Keyword 2
#0000ff	0	0	 //Keyword 3
#00008b	0	0	 //String
#006400	0	1	 //Comment
#ff0000	1	0	 //Preprocessor
#8b8b00	1	0	 //Number
#"""

## leet solarized ida theme. wow hacker.
DEFAULT_CLR = """
[DISASM]
000000	 //Instruction
aaaaaa	 //Directive
f3c5ff	 //Macro name
7e6082	 //Register name
666666	 //Other keywords
ffffff	 //Dummy data name
b9ebeb	 //Dummy code name
b9ebeb	 //Dummy unexplored name
bbecff	 //Hidden name
c0c0c0	 //Library function name
00d269	 //Local variable name
00ff00	 //Regular data name
3250d2	 //Regular code name
4646ff	 //Regular unexplored name
7faaff	 //Demangled name
617c7c	 //Segment name
3250d2	 //Imported name
008080	 //Suspicious constant
3734ff	 //Char in instruction
c0c0c0	 //String in instruction
595959	 //Number in instruction
f3c5ff	 //Char in data
ffaaff	 //String in data
00d2ff	 //Number in data
ffff00	 //Code reference
0080ff	 //Data reference
00d2ff	 //Code reference to tail
00d69d	 //Data reference to tail
7e07df	 //Automatic comment
00d269	 //Regular comment
00f379	 //Repeatable comment
3250d2	 //Extra line
ababab	 //Collapsed line
adad73	 //Line prefix: library function
fd5aff	 //Line prefix: regular function
7fffff	 //Line prefix: instruction
00ffaa	 //Line prefix: data
00d2ff	 //Line prefix: unexplored
ffaaff	 //Line prefix: externs
00ffff	 //Line prefix: current item
000000	 //Line prefix: current line
2d2d2d	 //Punctuation
32ade1	 //Opcode bytes
ffff00	 //Manual operand
666666	 //Error
0000aa	 //Default color
41c88e	 //Selected
009d9d	 //Library function
ff55ff	 //Regular function
000000	 //Single instruction
00aaff	 //Data bytes
000000	 //Unexplored byte
[NAVBAR]
ffaa00	 //Library function
00aaff	 //Regular function
000080	 //Instruction
b9ebeb	 //Data item
007878	 //Unexplored
ff00ff	 //External symbol
0000ca	 //Errors
4a4a4a	 //Gaps
00ff80	 //Cursor
0080ff	 //Address
[DEBUG]
ffd060	 //Current IP
32ade1	 //Current IP (Enabled)
408020	 //Current IP (Disabled)
2d2d2d	 //Default Background
000076	 //Address
00ff00	 //Address (Enabled)
004080	 //Address (Disabled)
0080ff	 //Address (Unavailible)
000000	 //Registers
ff0000	 //Registers (Changed)
800080	 //Registers (Edited)
[ARROW]
34466c	 //Jump in current function
dede00	 //Jump external to function
00aaff	 //Jump under the cursor
008000	 //Jump target
ff4040	 //Register target
[GRAPH]
b2b2b2	 //Top color
b2b2b2	 //Bottom color
f5f5f5	 //Normal title
989faa	 //Selected title
54585e	 //Current title
00ffff	 //Group frame
242424	 //Node shadow
003900	 //Highlight color 1
00006d	 //Highlight color 2
0000ff	 //Foreign node
cb4300	 //Normal edge
009100	 //Yes edge
0000bc	 //No edge
ffaaaa	 //Highlighted edge
008ec6	 //Current edge
[MISC]
212121	 //Message text
d4d4d4	 //Message background
404080	 //Patched bytes
0080ff	 //Unsaved changes
00c61a	 //Highlight color
3d3d3d	 //Hint color
"""

def color_format(val):
    t = "".join(["{:02x}".format((val >> i) & 0xff) for i in [0, 8, 16]])
    return "{}".format(t)

def color_by_name(colors, name):
    for c in colors:
        if c[1] == name:
            return "#" + color_format(c[0])
    return None

def graph_bounds(graph):
    """Bounding box of every exported coordinate: basic block rects and the
    polyline points of their edges."""
    xs, ys = [], []

    for b in graph["basic_blocks"]:
        if b["left"] < 0 and b["right"] < 0 and b["top"] < 0 and b["bottom"] < 0:
            continue  # dummy values used when the export had no graph layout
        xs += [b["left"], b["right"]]
        ys += [b["top"], b["bottom"]]

    for e in graph["edges"]:
        for c in e.get("coords", []):
            try:
                x, y = c.split(" ")
                xs.append(int(x))
                ys.append(int(y))
            except ValueError:
                continue

    if not xs:
        return 0, 0, 1, 1

    return min(xs), min(ys), max(xs), max(ys)


def decode_disasm_line(line):
    COLOR_BEGIN = 0x01
    COLOR_END = 0x02
    ptr = 0
    res = []
    colstack = []
    text = []
    line = line.strip(b"\x00")
    hidden_chars = 0

    while ptr < len(line):
        # print(ptr, len(line), line[ptr], colstack)
        if line[ptr] == COLOR_BEGIN:
            if line[ptr + 1] == 0x28:
                hidden_chars = 16  ## FIXME: Detect bitness here
            else:
                hidden_addr = False
                colstack.append(line[ptr + 1])
            ptr += 2
        elif line[ptr] == COLOR_END:
            col = colstack.pop()
            assert (col == line[ptr + 1])
            ptr += 2
            res.append((bytes(text).decode("utf-8"), col))
            text = []
        else:
            if hidden_chars == 0:
                text.append(line[ptr])
            else:
                hidden_chars -= 1
            ptr += 1

    return res

def parse_clr(fname):
    try:
        dat = open(fname, 'r').read().splitlines()
    except:
        dat = DEFAULT_CLR.splitlines()  # if file does not exist use the defaults

    res = []

    ign = False
    for i in range(len(dat)):
        if "[SYNTAX]" in dat[i]:
            ign = True  # Skip entries in the syntax section
            continue

        if "[" in dat[i] or "]" in dat[i]:
            ign = False
            continue

        if len(dat[i]) < 8 or ign == True:
            continue

        res.append([int(dat[i].split("\t")[0], 16), dat[i].split("\t")[1]])

        ## Normalize color name
        res[-1][1] = res[-1][1].strip(' /').replace(' ', '_').lower()

    return res

DISASM_TITLE_H = 16      # height of the block's title (address) bar
DISASM_LINE_H = 17.0     # vertical pitch of one disassembly line
DISASM_BOTTOM_PAD = 10   # padding below the last line
EDGE_W = 1.3             # edge line width, matching IDA's rendering
ARROW_L = 9              # arrowhead length
ARROW_W = 7              # arrowhead width at its base


def disasm_font_px(j_root):
    """Font size for the disassembly text.

    Two constraints, both measured against a real export:

    * Vertical: one line must fit DISASM_LINE_H (17px). At 12px the glyph box
      is ~15.6px, which leaves sensible leading inside 17px.
    * Horizontal: IDA sized the blocks for ~7.15px per character (measured
      across all blocks of a sample export: min 7.12, max 7.18). Monospace
      advance is 0.597em, so 12px gives 7.16px/char. The 1.5x of the reported
      font size that the SVG path used gives 8.06px/char, which pushes long
      lines outside their blocks.
    """
    return min(j_root["font_size"] * 4.0 / 3.0, DISASM_LINE_H * 0.72)


def css_color(colors, name, fallback):
    return color_by_name(colors, name) or fallback


def gen_css(colors, j_root):
    """Stylesheet for the page. Every colour is taken from the same palette the
    SVG output used, so the two look identical."""
    font_px = disasm_font_px(j_root)
    weight = "bold" if j_root["font_flags"] & 1 else "normal"
    out = []
    add = out.append

    add("html, body { margin: 0; padding: 0; height: 100%%; overflow: hidden;"
        " background: %s; color: #ddd; font-family: system-ui, -apple-system,"
        " 'Segoe UI', sans-serif; }" % css_color(colors, "bottom_color", "#1e1e1e"))
    add("#bar { position: fixed; top: 0; left: 0; right: 0; height: 40px; z-index: 100;"
        " display: flex; align-items: center; gap: 8px; padding: 0 12px;"
        " background: #252526; border-bottom: 1px solid #3c3c3c; font-size: 13px; }")
    add("#bar button { background: #3a3d41; color: #ddd; border: 1px solid #555;"
        " border-radius: 4px; padding: 4px 10px; cursor: pointer; font-size: 13px; }")
    add("#bar button:hover { background: #4a4d51; }")
    add("#bar .title { font-weight: 600; margin-right: 8px; }")
    add("#bar .hint, #bar .stat { color: #999; }")
    add("#bar .hint { margin-left: auto; }")
    add("#wrap { position: absolute; top: 40px; left: 0; right: 0; bottom: 0;"
        " overflow: hidden; cursor: grab; }")
    add("#wrap.dragging { cursor: grabbing; }")
    add("#world { position: absolute; top: 0; left: 0; transform-origin: 0 0; }")
    add("#canvas { position: absolute; top: 0; left: 0; }")

    # Blocks
    add(".block { position: absolute; box-sizing: border-box;"
        " background: %s; border: 1px solid %s; }" % (
            css_color(colors, "default_background", "#2d2d2d"),
            css_color(colors, "node_shadow", "#000")))
    add(".block.sel { outline: 2px solid #ffffff; outline-offset: -1px; }")
    add(".hdr { position: absolute; left: 0; top: 0; right: 0; height: %dpx;"
        " background: %s; border-bottom: 1px solid %s; box-sizing: border-box; }" % (
            DISASM_TITLE_H, css_color(colors, "normal_title", "#c0c0c0"),
            css_color(colors, "node_shadow", "#000")))
    add(".disasm { position: absolute; left: 4px; right: 4px; top: %dpx;"
        " line-height: %spx; white-space: pre; overflow: hidden;"
        " font-family: %s; font-size: %spx; font-weight: %s; }" % (
            DISASM_TITLE_H, DISASM_LINE_H, j_root["font_name"], font_px, weight))

    # Edges: each segment is a div rotated about the segment start. The gradient
    # trick scales it to exactly the segment length, so nothing needs measuring
    # at runtime.
    add(".edge { position: absolute; height: %spx; margin-top: %spx;"
        " background: var(--c, #888); transform-origin: 0 50%%; }"
        % (EDGE_W, -EDGE_W / 2.0))
    add(".arrow { position: absolute; width: 0; height: 0;"
        " border-style: solid; margin-top: %spx; transform-origin: 50%% 50%%; }" % (-ARROW_W / 2.0))

    for i in range(len(colors)):
        add(".txt_col_%02x { color: #%s; }" % (i, color_format(colors[i][0])))

    return "\n".join(out)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>@TITLE@</title>
<style>
@CSS@
</style>
</head>
<body>
<div id="bar">
  <span class="title">@TITLE@</span>
  <button id="bfit" title="Fit the whole graph in the window">Fit</button>
  <button id="bin" title="Zoom in">+</button>
  <button id="bout" title="Zoom out">&minus;</button>
  <button id="b1" title="Reset to 100%">100%</button>
  <span class="stat" id="stat"></span>
  <span class="hint">drag to pan &middot; wheel to zoom &middot; click a block to copy its address</span>
</div>
<div id="wrap"><div id="world"><div id="canvas">@CONTENT@</div></div></div>
<script>
(function () {
  var W = @WIDTH@, H = @HEIGHT@;
  var wrap = document.getElementById('wrap');
  var world = document.getElementById('world');
  var stat = document.getElementById('stat');
  var scale = 1, tx = 0, ty = 0;

  function apply() {
    world.style.transform =
      'translate(' + tx + 'px,' + ty + 'px) scale(' + scale + ')';
    stat.textContent = Math.round(scale * 100) + '%';
  }
  function center() {
    tx = (wrap.clientWidth - W * scale) / 2;
    ty = (wrap.clientHeight - H * scale) / 2;
    apply();
  }
  function fit() {
    scale = Math.min(wrap.clientWidth / W, wrap.clientHeight / H);
    center();
  }
  // Zoom about a point given in wrap coordinates, keeping that point fixed.
  function zoomAt(f, cx, cy) {
    var ns = Math.min(16, Math.max(0.01, scale * f));
    tx = cx - (cx - tx) * (ns / scale);
    ty = cy - (cy - ty) * (ns / scale);
    scale = ns;
    apply();
  }
  function zoomButton(f) {
    zoomAt(f, wrap.clientWidth / 2, wrap.clientHeight / 2);
  }

  // --- pan -------------------------------------------------------------
  // The anchor is kept in screen space, so it must be re-derived whenever the
  // transform changes underneath it; otherwise a wheel zoom during a drag
  // leaves it stale and the next mousemove jumps.
  var down = false, sx = 0, sy = 0;
  function syncAnchor(e) { sx = e.clientX - tx; sy = e.clientY - ty; }
  wrap.addEventListener('mousedown', function (e) {
    if (e.button !== 0) return;
    down = true; syncAnchor(e);
    wrap.classList.add('dragging');
  });
  window.addEventListener('mousemove', function (e) {
    if (!down) return;
    tx = e.clientX - sx; ty = e.clientY - sy;
    apply();
  });
  window.addEventListener('mouseup', function () {
    down = false; wrap.classList.remove('dragging');
  });
  // Middle drag pans too.
  wrap.addEventListener('mousedown', function (e) {
    if (e.button === 1) e.preventDefault();
  });

  wrap.addEventListener('wheel', function (e) {
    e.preventDefault();
    var r = wrap.getBoundingClientRect();
    zoomAt(e.deltaY < 0 ? 1.15 : 1 / 1.15, e.clientX - r.left, e.clientY - r.top);
    if (down) syncAnchor(e);
  }, { passive: false });

  // --- selection -------------------------------------------------------
  // Clicks are swallowed while dragging, so a pan never changes the selection.
  var moved = false;
  wrap.addEventListener('mousedown', function () { moved = false; });
  window.addEventListener('mousemove', function (e) {
    if (down && (Math.abs(e.clientX - (sx + tx)) > 3 || Math.abs(e.clientY - (sy + ty)) > 3))
      moved = true;
  });
  document.getElementById('canvas').addEventListener('click', function (e) {
    if (moved) return;
    var b = e.target.closest ? e.target.closest('.block') : null;
    var prev = document.querySelector('.block.sel');
    if (prev) prev.classList.remove('sel');
    if (!b) return;
    b.classList.add('sel');
    var addr = b.getAttribute('data-addr');
    if (addr && navigator.clipboard) navigator.clipboard.writeText(addr).catch(function () {});
  });

  document.getElementById('bfit').addEventListener('click', fit);
  document.getElementById('bin').addEventListener('click', function () { zoomButton(1.25); });
  document.getElementById('bout').addEventListener('click', function () { zoomButton(0.8); });
  document.getElementById('b1').addEventListener('click', function () { scale = 1; center(); });

  window.addEventListener('resize', function () { center(); });
  fit();
})();
</script>
</body>
</html>
"""
def build_edges(graph, ox, oy):
    """Edges as chains of rotated divs.

    IDA exports each edge as a routed polyline. Each segment becomes a div
    scaled to the segment length by the background-gradient trick and rotated
    about its start point, with a CSS triangle at the tip oriented to the final
    segment. No SVG and no canvas, and nothing is measured at runtime.
    """
    out = []
    arrows = []

    for e in graph["edges"]:
        pts = []
        for c in e.get("coords", []):
            try:
                x, y = c.split(" ")
                pts.append((int(x) - ox, int(y) - oy))
            except ValueError:
                continue
        if len(pts) < 2:
            continue

        # Shorten the last segment so the line stops under the arrowhead
        # instead of poking out of its tip.
        (x0, y0), (x1, y1) = pts[-2], pts[-1]
        seg = math.hypot(x1 - x0, y1 - y0)
        if seg > 0:
            k = max(0.0, (seg - ARROW_L) / seg)
            x1 = x0 + (x1 - x0) * k
            y1 = y0 + (y1 - y0) * k
            pts[-1] = (x1, y1)

        r, g, b = [(e["color"] >> i) & 0xFF for i in [0, 8, 16]]
        col = "rgb(%d,%d,%d)" % (r, g, b)

        for i in range(len(pts) - 1):
            (px, py), (qx, qy) = pts[i], pts[i + 1]
            dx, dy = qx - px, qy - py
            length = math.hypot(dx, dy)
            if length < 0.5:
                continue
            ang = math.degrees(math.atan2(dy, dx))
            out.append(
                '<div class="edge" style="--c:%s;left:%.1fpx;top:%.1fpx;'
                'width:%.1fpx;transform:rotate(%.2fdeg)"></div>'
                % (col, px, py, length, ang))

        # Arrowhead orientation comes from the original final segment, before
        # the shortening above, so it always matches the true edge direction.
        (ax0, ay0), (ax1, ay1) = pts[-2], pts[-1]
        ang = math.degrees(math.atan2(ay1 - ay0, ax1 - ax0))
        arrows.append(
            '<div class="arrow" style="left:%.1fpx;top:%.1fpx;'
            'border-width:%.1fpx 0 %.1fpx %.1fpx;'
            'border-color:transparent transparent transparent %s;'
            'transform:rotate(%.2fdeg)"></div>'
            % (ax1, ay1, ARROW_W / 2.0, ARROW_W / 2.0, ARROW_L, col, ang))

    # Arrowheads last so they sit above the lines they terminate.
    return "".join(out) + "".join(arrows)


def build_blocks(graph, ox, oy):
    """Basic blocks as positioned divs with their disassembly as inline spans."""
    out = []
    for b in graph["basic_blocks"]:
        lines = []
        for l in b["disasm_lines"]:
            parts = decode_disasm_line(base64.b64decode(l["text"]))
            lines.append('<div class="ln">' + "".join(
                '<span class="txt_col_%02x">%s</span>' % (c, escape(t))
                for t, c in parts) + '</div>')
        out.append(
            '<div class="block" data-addr="%#x" style="left:%dpx;top:%dpx;'
            'width:%dpx;height:%dpx"><div class="hdr"></div>'
            '<div class="disasm">%s</div></div>'
            % (b["addr_start"], b["left"] - ox, b["top"] - oy,
               max(b["right"] - b["left"], 1), max(b["bottom"] - b["top"], 1),
               "".join(lines)))
    return "".join(out)


def to_html(j_root, graph, outname, title):
    colors = parse_clr(None)
    minx, miny, maxx, maxy = graph_bounds(graph)
    pad = 20
    ox, oy = minx - pad, miny - pad
    width = max(maxx - minx, 1) + 2 * pad
    height = max(maxy - miny, 1) + 2 * pad

    content = build_edges(graph, ox, oy) + build_blocks(graph, ox, oy)

    doc = (HTML_TEMPLATE
           .replace("@CSS@", gen_css(colors, j_root))
           .replace("@CONTENT@", content)
           .replace("@TITLE@", escape(title))
           .replace("@WIDTH@", str(width))
           .replace("@HEIGHT@", str(height)))

    with open(outname, "w") as f:
        f.write(doc)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: {} <export.json> [output.html]".format(
            os.path.basename(sys.argv[0])))
        sys.exit(-1)

    j_root = json.loads(open(sys.argv[1], 'r').read())
    if not j_root.get("functions"):
        print("No function in {}.".format(sys.argv[1]))
        sys.exit(-1)

    graph = j_root["functions"][0]
    outname = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(sys.argv[1])[0] + ".html"
    title = "{} – {}".format(graph.get("name", "graph"), os.path.basename(sys.argv[1]))

    to_html(j_root, graph, outname, title)
    print("wrote {}".format(outname))
