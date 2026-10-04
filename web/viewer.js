/*
 * Shared viewer for exported IDA graph views.
 *
 * The graph arrives in the URL fragment as base64url(JSON), compressed with
 * miniz if the exporter compressed it. A fragment never leaves the browser, so
 * the page still works from file:// and on an offline machine; nothing about
 * the graph is sent to the server that serves this file.
 *
 * The geometry below deliberately mirrors cpp/IdaGraph/html_export.cpp: block
 * placement, edge routing and the pastel bundle colours are computed the same
 * way, so this viewer and the plugin's own inline renderer agree.
 */
(function () {
  "use strict";

  // ------------------------------------------------ palette (from CLR_VALUES)
  var CLR_VALUES = [
    0x000000, 0xaaaaaa, 0xf3c5ff, 0x7e6082, 0x666666, 0xffffff, 0xb9ebeb, 0xb9ebeb, 0xbbecff, 0xc0c0c0, 0x00d269, 0x00ff00,
    0x3250d2, 0x4646ff, 0x7faaff, 0x617c7c, 0x3250d2, 0x008080, 0x3734ff, 0xc0c0c0, 0x595959, 0xf3c5ff, 0xffaaff, 0x00d2ff,
    0xffff00, 0x0080ff, 0x00d2ff, 0x00d69d, 0x7e07df, 0x00d269, 0x00f379, 0x3250d2, 0xababab, 0xadad73, 0xfd5aff, 0x7fffff,
    0x00ffaa, 0x00d2ff, 0xffaaff, 0x00ffff, 0x000000, 0x2d2d2d, 0x32ade1, 0xffff00, 0x666666, 0x0000aa, 0x41c88e, 0x009d9d,
    0xff55ff, 0x000000, 0x00aaff, 0x000000, 0xffaa00, 0x00aaff, 0x000080, 0xb9ebeb, 0x007878, 0xff00ff, 0x0000ca, 0x4a4a4a,
    0x00ff80, 0x0080ff, 0xffd060, 0x32ade1, 0x408020, 0x2d2d2d, 0x000076, 0x00ff00, 0x004080, 0x0080ff, 0x000000, 0xff0000,
    0x800080, 0x34466c, 0xdede00, 0x00aaff, 0x008000, 0xff4040, 0xb2b2b2, 0xb2b2b2, 0xf5f5f5, 0x989faa, 0x54585e, 0x00ffff,
    0x242424, 0x003900, 0x00006d, 0x0000ff, 0xcb4300, 0x009100, 0x0000bc, 0xffaaaa, 0x008ec6, 0x212121, 0xd4d4d4, 0x404080,
    0x0080ff, 0x00c61a, 0x3d3d3d
  ];
  var EDGE_PASTELS = [
    0xdba276, 0x9473de, 0xd47dae, 0x73b1de, 0xa0d47d,
    0x7bced5, 0xdb9275, 0xc47dd4, 0x7db1d4, 0xbfd47d
  ];

  // ------------------------------------------------------------- styles
  /* IDA sizes every block as 26 + 19 * lines: a 16px title, the disassembly
   * lines, and 10px of padding under the last one. LINE_H is the pitch that
   * falls out of that for a typical block, and is only the fallback — each
   * block derives its own pitch from its height below, so the text still fits
   * whatever layout a given export used. */
  var TITLE_H = 16, LINE_H = 19.0, BOTTOM_PAD = 10, FONT_PX = 11.8;
  var BUNDLE_DISTANCE = 24.0, BUNDLE_OVERLAP = 20.0;
  var MIN_SCALE = 0.01, MAX_SCALE = 16;
  /* Touch frames coalesce and arrive late, so one frame can carry a large
   * finger movement. Bound how far a single frame may change the scale, so a
   * bad frame cannot throw the view across the graph. */
  var MAX_STEP = 2.5;
  /* Below this separation a two-finger ratio is too unstable to trust. */
  var PINCH_MIN = 8;
  /* The most a pinch may move the view in one frame. A finger cannot cover
   * this much ground in 16ms, so exceeding it means the reported geometry
   * changed for a reason the gesture did not intend — a coalesced frame, a
   * pointer the driver re-identified, or a page zoom rescaling the client
   * coordinates. Rather than follow it, the gesture re-baselines. */
  var MAX_PAN_STEP = 200;

  var css = [
    "html,body{margin:0;padding:0;height:100%;overflow:hidden;background:#1e1e1e;",
    "touch-action:none;overscroll-behavior:none;",
    "color:#ddd;font-family:system-ui,-apple-system,'Segoe UI',sans-serif}",
    "#bar{position:fixed;top:0;left:0;right:0;height:40px;z-index:100;display:flex;",
    "align-items:center;gap:8px;padding:0 12px;background:#252526;",
    "border-bottom:1px solid #3c3c3c;font-size:13px}",
    "#bar button{background:#3a3d41;color:#ddd;border:1px solid #555;border-radius:4px;",
    "padding:4px 10px;cursor:pointer;font-size:13px}",
    "#bar button:hover{background:#4a4d51}",
    "#bar .title{font-weight:600;margin-right:8px;flex:0 1 auto;min-width:0;",
    "overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
    "#bar .stat{color:#999;margin-left:auto;white-space:nowrap}",
    "#wrap{position:absolute;top:40px;left:0;right:0;bottom:0;overflow:hidden;",
    "cursor:grab;touch-action:none}#wrap.dragging{cursor:grabbing}",
    "#world{position:absolute;top:0;left:0;transform-origin:0 0;will-change:transform}",
    "#canvas{position:absolute;top:0;left:0}",
    ".edges{position:absolute;top:0;left:0;overflow:visible;pointer-events:none}",
    ".block{position:absolute;box-sizing:border-box;background:#2d2d2d;border:1px solid #000}",
    ".block.sel{outline:2px solid #fff;outline-offset:-1px}",
    ".hdr{position:absolute;left:0;top:0;right:0;height:" + TITLE_H +
      "px;background:#c0c0c0;border-bottom:1px solid #000;box-sizing:border-box}",
    /* The disassembly only lines up in a monospace face, so the chain has to
     * end in the generic keyword: if the named font is missing the browser
     * would otherwise substitute a proportional one and every column drifts. */
    ".disasm{position:absolute;left:3px;right:3px;top:" + TITLE_H +
      "px;line-height:" + LINE_H + "px;white-space:pre;overflow:hidden;" +
      "font-family:'FreeMono','DejaVu Sans Mono','Liberation Mono'," +
      "'Noto Sans Mono','Courier New',monospace;" +
      "font-kerning:none;font-variant-ligatures:none;" +
      "font-size:" + FONT_PX + "px;font-weight:bold}",
    // A line with no text must still occupy its slot: IDA gives every line a
    // row, and without a minimum height empty ones collapse and pull the rest
    // of the block's text upward.
    ".ln{min-height:" + LINE_H + "px}",
    "#err{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;",
    "flex-direction:column;gap:10px;text-align:center;padding:24px;color:#e0a0a0}"
  ].join("");
  for (var i = 0; i < CLR_VALUES.length; i++) {
    css += ".txt_col_" + hex2(i) + "{color:#" + cssColor(CLR_VALUES[i]) + "}";
  }

  function hex2(n) { return (n < 16 ? "0" : "") + n.toString(16); }

  /* IDA packs colours as 0xBBGGRR, the same order the C++ color_hex() writes. */
  function cssColor(v) {
    return b2(v & 0xff) + b2((v >> 8) & 0xff) + b2((v >> 16) & 0xff);
  }
  function b2(n) { return (n < 16 ? "0" : "") + n.toString(16); }

  // --------------------------------------------------------- data loading
  function base64urlToBytes(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  /* The plugin flate-compresses the payload, so try decompressing first and
   * fall back to raw text when that fails (an uncompressed export, or a
   * fragment someone hand-edited). */
  function bytesToText(bytes) {
    if (typeof DecompressionStream !== "function") {
      try {
        return Promise.resolve(new TextDecoder("utf-8").decode(bytes));
      } catch (e) {
        return Promise.reject(new Error(
          "This browser cannot decompress the graph. Use a recent Chrome, " +
          "Edge, Firefox or Safari."));
      }
    }
    var ds = new DecompressionStream("deflate");
    var stream = new Blob([bytes]).stream().pipeThrough(ds);
    return new Response(stream).text().catch(function () {
      return new TextDecoder("utf-8").decode(bytes);
    });
  }

  function readGraph() {
    var hash = location.hash || "";
    var m = /[#&]d=([^&]*)/.exec(hash);
    if (!m) return Promise.reject(new Error("No graph data in the link."));
    try {
      return bytesToText(base64urlToBytes(m[1]))
        .then(JSON.parse)
        .then(function (o) { return o.functions[0]; });
    } catch (e) {
      return Promise.reject(e);
    }
  }

  // ------------------------------------------------------------- geometry
  function bounds(g) {
    var b = { x0: 1e18, y0: 1e18, x1: -1e18, y1: -1e18 }, any = false;
    g.basic_blocks.forEach(function (bb) {
      if (bb.left < 0 && bb.right < 0 && bb.top < 0 && bb.bottom < 0) return;
      b.x0 = Math.min(b.x0, bb.left); b.y0 = Math.min(b.y0, bb.top);
      b.x1 = Math.max(b.x1, bb.right); b.y1 = Math.max(b.y1, bb.bottom);
      any = true;
    });
    g.edges.forEach(function (e) {
      (e.coords || []).forEach(function (c) {
        var p = c.split(" ");
        var x = parseFloat(p[0]), y = parseFloat(p[1]);
        if (isNaN(x) || isNaN(y)) return;
        b.x0 = Math.min(b.x0, x); b.y0 = Math.min(b.y0, y);
        b.x1 = Math.max(b.x1, x); b.y1 = Math.max(b.y1, y);
        any = true;
      });
    });
    return any ? b : { x0: 0, y0: 0, x1: 1, y1: 1 };
  }

  function segments(pts) {
    var out = [];
    for (var i = 1; i < pts.length; i++) {
      var x = pts[i - 1][0], y = pts[i - 1][1];
      var dx = pts[i][0] - x, dy = pts[i][1] - y;
      var len = Math.hypot(dx, dy);
      if (len >= 0.5) out.push({ x: x, y: y, dx: dx / len, dy: dy / len, length: len });
    }
    out.sort(function (a, b) { return b.length - a.length; });
    return out.slice(0, 3);
  }

  function runTogether(a, b) {
    var dot = a.dx * b.dx + a.dy * b.dy;
    if (Math.abs(dot) < 0.98) return false;
    var rx = b.x - a.x, ry = b.y - a.y;
    if (Math.abs(rx * a.dy - ry * a.dx) > BUNDLE_DISTANCE) return false;
    var start = rx * a.dx + ry * a.dy, finish = start + dot * b.length;
    if (finish < start) { var t = start; start = finish; finish = t; }
    return Math.min(a.length, finish) - Math.max(0, start) >= BUNDLE_OVERLAP;
  }

  /* Lines that share a nearby, roughly parallel corridor get the same pastel,
   * the same way the plugin colours them, so a bundle reads as a group. */
  function colourEdges(edges) {
    edges.forEach(function (e, i) { e.color = EDGE_PASTELS[i % EDGE_PASTELS.length]; });
    var runs = edges.map(segments);
    var parent = edges.map(function (_, i) { return i; });
    function root(i) { while (parent[i] !== i) { parent[i] = parent[parent[i]]; i = parent[i]; } return i; }
    for (var i = 0; i < edges.length; i++) {
      for (var j = i + 1; j < edges.length; j++) {
        if (edges[i].base_color !== edges[j].base_color) continue;
        var close = false;
        runs[i].forEach(function (a) {
          runs[j].forEach(function (b) { if (runTogether(a, b)) close = true; });
        });
        if (close) parent[root(j)] = root(i);
      }
    }
    var groups = {};
    edges.forEach(function (_, i) { (groups[root(i)] = groups[root(i)] || []).push(i); });
    Object.keys(groups).forEach(function (k) {
      var idx = groups[k];
      if (idx.length < 2) return;
      idx.sort(function (a, b) {
        function lateral(i) {
          var s = runs[i][0], dx = s.dx, dy = s.dy;
          if (dx < 0 || (dx === 0 && dy < 0)) { dx = -dx; dy = -dy; }
          return -dy * (s.x + s.dx * s.length / 2) + dx * (s.y + s.dy * s.length / 2);
        }
        return lateral(a) - lateral(b);
      });
      idx.forEach(function (ei, rank) { edges[ei].color = EDGE_PASTELS[rank % EDGE_PASTELS.length]; });
    });
  }

  // ----------------------------------------------------------- disassembly
  /* 0x01 <idx> opens a coloured run, 0x02 <idx> closes it; 0x01 0x28 marks an
   * address the exporter stripped, and a trailing 0x00 terminates the line.
   * Mirrors decode_line() in the plugin.
   *
   * Runs are flushed when they close AND when the line ends: a line with no
   * colour markers at all (a comment such as "; __unwind {") has nothing to
   * close it, so flushing only on 0x02 would drop it. */
  function decodeLine(bytes) {
    var out = [], stack = [], text = "", hidden = 0, p = 0;
    /* A run takes the colour being closed when the 0x02 arrives, and the
     * colour still open when the line simply ends. */
    function flush(color) {
      if (text === "") return;
      if (color === undefined) color = stack.length ? stack[stack.length - 1] : 0;
      out.push([text, color]);
      text = "";
    }
    while (p < bytes.length) {
      var c = bytes[p];
      if (c === 1) {
        if (bytes[p + 1] === 0x28) hidden = 16;
        else stack.push(bytes[p + 1]);
        p += 2;
      } else if (c === 2) {
        flush(stack.length ? stack.pop() : 0);
        p += 2;
      } else if (c === 0) {
        p++;                 // terminator, not content
      } else {
        if (hidden === 0) text += String.fromCharCode(c); else hidden--;
        p++;
      }
    }
    flush();
    return out;
  }

  function b64ToBytes(s) {
    var bin = atob(s.replace(/\s/g, "")), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  // --------------------------------------------------------------- render
  function render(g, W, H) {
    var html = '<svg class="edges" width="' + Math.round(W) + '" height="' + Math.round(H) +
      '" xmlns="http://www.w3.org/2000/svg"><defs>';

    var seen = {};
    g.edges.forEach(function (e) {
      var c = cssColor(e.color);
      if (seen[c]) return;
      seen[c] = 1;
      html += '<marker id="ar' + c + '" viewBox="0 0 10 10" refX="3" refY="5" ' +
        'markerWidth="7" markerHeight="7" orient="auto" markerUnits="strokeWidth">' +
        '<path d="M3,2 L10,5 L3,8 z" fill="#' + c + '"/></marker>';
    });
    html += "</defs>";

    g.edges.forEach(function (e) {
      var pts = (e.coords || []).map(function (c) {
        var p = c.split(" ");
        return [parseFloat(p[0]) - oxGlobal, parseFloat(p[1]) - oyGlobal];
      }).filter(function (p) { return !isNaN(p[0]) && !isNaN(p[1]); });
      if (pts.length < 2) return;
      // Drop repeated routing points: a zero-length tail gives orient="auto"
      // no direction to work with.
      for (var i = 1; i < pts.length;) {
        if (Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]) < 0.5) pts.splice(i, 1);
        else i++;
      }
      if (pts.length < 2) return;
      var end = pts[pts.length - 1], prev = pts[pts.length - 2];
      var dx = end[0] - prev[0], dy = end[1] - prev[1];
      var len = Math.hypot(dx, dy);
      var shorten = Math.min(9.8, len * 0.5);
      pts[pts.length - 1] = [end[0] - shorten * dx / len, end[1] - shorten * dy / len];

      var d = pts.map(function (p, i) { return (i ? "L" : "M") + p[0].toFixed(2) + "," + p[1].toFixed(2); }).join(" ");
      var c = cssColor(e.color);
      html += '<path d="' + d + '" fill="none" stroke="#' + c + '" stroke-width="2" ' +
        'stroke-linejoin="round" marker-end="url(#ar' + c + ')"/>';
    });
    html += "</svg>";

    g.basic_blocks.forEach(function (b) {
      var lines = "";
      var n = (b.disasm_lines || []).length;
      /* Derive the line pitch from this block's own height rather than
       * assuming one. The block's rect is the ground truth: whatever pitch
       * makes the lines fill it without passing its bottom is the right one,
       * and for a normal export that is exactly the 19px IDA used. Capping at
       * LINE_H keeps an unusually tall block from spreading its lines out. */
      var avail = (b.bottom - b.top) - TITLE_H - BOTTOM_PAD;
      var pitch = n > 0 ? Math.min(LINE_H, avail / n) : LINE_H;
      if (!(pitch > 0)) pitch = LINE_H;
      (b.disasm_lines || []).forEach(function (l) {
        lines += '<div class="ln" style="line-height:' + pitch.toFixed(2) + "px;min-height:" +
          pitch.toFixed(2) + 'px">';
        decodeLine(b64ToBytes(l.text)).forEach(function (seg) {
          lines += '<span class="txt_col_' + hex2(seg[1]) + '">' + esc(seg[0]) + "</span>";
        });
        lines += "</div>";
      });
      html += '<div class="block" data-addr="0x' + (b.addr_start >>> 0).toString(16) +
        '" style="left:' + Math.round(b.left - oxGlobal) + "px;top:" + Math.round(b.top - oyGlobal) +
        "px;width:" + Math.max(1, Math.round(b.right - b.left)) +
        "px;height:" + Math.max(1, Math.round(b.bottom - b.top)) +
        'px"><div class="hdr"></div><div class="disasm">' + lines + "</div></div>";
    });
    return html;
  }

  var oxGlobal = 0, oyGlobal = 0, W = 1, H = 1;

  // ------------------------------------------------------------- controls
  function start(html) {
    var style = document.createElement("style");
    style.textContent = css;
    document.head.appendChild(style);
    document.getElementById("root").innerHTML =
      '<div id="bar"><span class="title"></span>' +
      '<button id="bfit">Fit</button><button id="bin">+</button>' +
      '<button id="bout">&minus;</button><button id="b1">100%</button>' +
      '<span class="stat" id="stat"></span></div>' +
      '<div id="wrap"><div id="world"><div id="canvas">' + html + "</div></div></div>";
    document.querySelector("#bar .title").textContent = document.title;

    var wrap = document.getElementById("wrap"), world = document.getElementById("world");
    var stat = document.getElementById("stat");
    var s = 1, tx = 0, ty = 0;

    function ap() {
      world.style.transform = "translate(" + tx + "px," + ty + "px) scale(" + s + ")";
      stat.textContent = Math.round(s * 100) + "%";
    }
    function ct() { tx = (wrap.clientWidth - W * s) / 2; ty = (wrap.clientHeight - H * s) / 2; ap(); }
    function ft() { s = Math.min(wrap.clientWidth / W, wrap.clientHeight / H); ct(); }
    // Open on the entry block at a readable zoom rather than fitting everything.
    function focusFirst() {
      var first = document.querySelector("#canvas .block");
      if (!first) { ft(); return; }
      var w = first.offsetWidth, h = first.offsetHeight;
      s = Math.min(1, wrap.clientWidth / (w + 40), wrap.clientHeight / (h + 40));
      tx = wrap.clientWidth / 2 - (first.offsetLeft + w / 2) * s;
      ty = wrap.clientHeight / 2 - (first.offsetTop + h / 2) * s;
      ap();
    }
    /* Zoom by `f` about a point in wrap-local coordinates. */
    function za(f, cx, cy) {
      var n = Math.min(MAX_SCALE, Math.max(MIN_SCALE, s * f));
      tx = cx - (cx - tx) * (n / s); ty = cy - (cy - ty) * (n / s); s = n; ap();
    }

    /* Pointer events cover mouse, touch and pen alike, so the same code pans
     * on a phone as on a desktop. Wheel and pinch are handled separately. */
    var pts = new Map(), panning = false, sx = 0, sy = 0;
    var anchor = null;   // pinch baseline; see beginPinch()

    function onText(e) {
      return !!(e.target && e.target.closest && e.target.closest(".disasm"));
    }
    function ptsArr() { var a = []; pts.forEach(function (p) { a.push(p); }); return a; }
    function mid(a) { return [(a[0].x + a[1].x) / 2, (a[0].y + a[1].y) / 2]; }
    function dist(a) { return Math.hypot(a[0].x - a[1].x, a[0].y - a[1].y); }

    /* Start tracking a pinch. The baseline is deliberately NOT taken here.
     * Touch drivers commonly report both contacts at nearly the same spot and
     * settle them over the following frames, and a fast move can arrive in the
     * same frame as the second touchdown. Anchoring on either would set a
     * near-zero reference distance and make the first ratio enormous. The
     * baseline is taken from the first frame that has a usable separation
     * instead, and that frame does not zoom.
     *
     * The two pointer ids are recorded so the gesture can be re-baselined
     * whenever the pair being measured changes — a finger lifted or added
     * while others stay down — since a distance taken across a different pair
     * than the baseline was measured on is meaningless. */
    function beginPinch() {
      anchor = { armed: false, idA: null, idB: null, d0: 1, s0: s, tx0: tx, ty0: ty,
                 mid0x: 0, mid0y: 0, dPrev: 1 };
      panning = false;
    }

    /* Re-derive the transform from the baseline, so the content point under
     * the baseline midpoint stays under the current midpoint. Combined with
     * the frozen reference distance this is scale-invariant: a move of the
     * same on-screen size changes the scale by the same ratio at any zoom
     * level, which is what stops a pinch from lurching.
     *
     * The distance used is bounded against the previous frame's, so a single
     * coalesced frame cannot carry the scale away. Bounding the distance
     * rather than the ratio keeps the direction of travel honest: whatever the
     * fingers did, the view moves the same way. */
    function updatePinch(a) {
      if (!anchor || a.length < 2) return;
      // A different pair than the baseline was taken on: start over rather
      // than compare distances that are not measuring the same thing.
      if (anchor.idA !== null && (anchor.idA !== a[0].id || anchor.idB !== a[1].id)) {
        beginPinch();
        return;
      }
      var d = dist(a);
      if (d < PINCH_MIN) return;
      var r = wrap.getBoundingClientRect();
      var m = mid(a);
      if (!anchor.armed) {
        anchor.armed = true;
        anchor.idA = a[0].id; anchor.idB = a[1].id;
        anchor.d0 = d; anchor.s0 = s;
        anchor.tx0 = tx; anchor.ty0 = ty;
        anchor.mid0x = m[0] - r.left; anchor.mid0y = m[1] - r.top;
        anchor.dPrev = d;
        return;                     // establish the reference, do not zoom
      }
      var dEff = Math.min(anchor.dPrev * MAX_STEP, Math.max(anchor.dPrev / MAX_STEP, d));
      anchor.dPrev = dEff;
      var f = dEff / anchor.d0;
      var s1 = Math.min(MAX_SCALE, Math.max(MIN_SCALE, anchor.s0 * f));
      var ax = (anchor.mid0x - anchor.tx0) / anchor.s0;  // content point
      var ay = (anchor.mid0y - anchor.ty0) / anchor.s0;
      var ntx = (m[0] - r.left) - ax * s1;
      var nty = (m[1] - r.top) - ay * s1;
      /* Last line of defence: whatever produced this frame, do not let it drag
       * the view further than a finger could have. Re-baselining drops the
       * frame and the next one is measured from where the view already is. */
      if (Math.hypot(ntx - tx, nty - ty) > MAX_PAN_STEP) {
        anchor.d0 = d; anchor.s0 = s; anchor.tx0 = tx; anchor.ty0 = ty;
        anchor.mid0x = m[0] - r.left; anchor.mid0y = m[1] - r.top;
        anchor.dPrev = d;
        return;
      }
      tx = ntx; ty = nty; s = s1;
      ap();
    }

    wrap.addEventListener("pointerdown", function (e) {
      // Pressing the disassembly with a mouse should still select text.
      if (e.pointerType === "mouse" && (e.button !== 0 || onText(e))) return;
      pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
      try { wrap.setPointerCapture(e.pointerId); } catch (_) {}
      // The viewport can shrink mid-gesture (the URL bar hiding), and the
      // stored anchor would then describe a frame that no longer exists.
      anchor = null;
      if (pts.size === 1) {
        panning = true;
        sx = e.clientX - tx; sy = e.clientY - ty;
        wrap.classList.add("dragging");
      } else if (pts.size === 2) {
        beginPinch();
      } else {
        panning = false;
      }
      e.preventDefault();
    }, { passive: false });

    wrap.addEventListener("pointermove", function (e) {
      if (!pts.has(e.pointerId)) return;
      pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (pts.size >= 2) {
        updatePinch(ptsArr());
      } else if (panning) {
        tx = e.clientX - sx; ty = e.clientY - sy; ap();
      }
      e.preventDefault();
    }, { passive: false });

    function endPointer(e) {
      if (!pts.has(e.pointerId)) return;
      pts.delete(e.pointerId);
      // Lifting one finger of a pinch hands the gesture back to panning,
      // re-anchored so the view does not jump as the finger count drops.
      if (pts.size === 1) {
        var a = ptsArr();
        anchor = null;        panning = true; sx = a[0].x - tx; sy = a[0].y - ty;
      } else if (pts.size === 0) {
        panning = false; anchor = null; wrap.classList.remove("dragging");
      }
    }
    wrap.addEventListener("pointerup", endPointer);
    wrap.addEventListener("pointercancel", endPointer);
    // Mobile browsers occasionally drop a pointerup, leaving a ghost pointer
    // that would corrupt every gesture after it, so the state is cleared once
    // no button or contact remains down.
    window.addEventListener("pointerup", endPointer);
    window.addEventListener("pointercancel", endPointer);
    function resetIfIdle(e) {
      if (pts.size === 0) return;
      if (e && e.buttons === 0 && e.pointerType === "mouse") {
        pts.clear(); panning = false; anchor = null;
        wrap.classList.remove("dragging");
      }
    }
    window.addEventListener("pointerup", resetIfIdle);
    window.addEventListener("pointercancel", resetIfIdle);
    window.addEventListener("blur", function () {
      pts.clear(); panning = false; anchor = null;
      wrap.classList.remove("dragging");
    });

    wrap.addEventListener("wheel", function (e) {
      e.preventDefault();
      var r = wrap.getBoundingClientRect();
      za(e.deltaY < 0 ? 1.15 : 1 / 1.15, e.clientX - r.left, e.clientY - r.top);
      if (panning) { sx = e.clientX - tx; sy = e.clientY - ty; }
    }, { passive: false });
    /* Safari delivers its page pinch-zoom as gesture events regardless of
     * touch-action, and zooming the page rescales the client coordinates the
     * pan and pinch read, which looks exactly like the view jumping. */
    ["gesturestart", "gesturechange", "gestureend"].forEach(function (t) {
      wrap.addEventListener(t, function (e) { e.preventDefault(); }, { passive: false });
      document.addEventListener(t, function (e) { e.preventDefault(); }, { passive: false });
    });

    document.getElementById("bfit").addEventListener("click", ft);
    document.getElementById("bin").addEventListener("click", function () { za(1.25, wrap.clientWidth / 2, wrap.clientHeight / 2); });
    document.getElementById("bout").addEventListener("click", function () { za(0.8, wrap.clientWidth / 2, wrap.clientHeight / 2); });
    document.getElementById("b1").addEventListener("click", function () { s = 1; ct(); });
    /* A phone resizes the viewport whenever the URL bar shows or hides, which
     * can happen mid-gesture. Re-centring on every resize would throw the view
     * across the graph for no reason the user asked for, so the content point
     * at the middle of the view is held in place instead. */
    var lastW = wrap.clientWidth, lastH = wrap.clientHeight;
    function onResize() {
      var nw = wrap.clientWidth, nh = wrap.clientHeight;
      if (nw === lastW && nh === lastH) return;
      var cx = nw / 2, cy = nh / 2;
      var ax = (lastW / 2 - tx) / s, ay = (lastH / 2 - ty) / s;
      tx = cx - ax * s; ty = cy - ay * s;
      lastW = nw; lastH = nh;
      ap();
    }
    window.addEventListener("resize", onResize);
    focusFirst();
  }

  // ----------------------------------------------------------------- init
  readGraph().then(function (g) {
    if (typeof g.name === "string" && g.name) {
      document.title = g.name;
      var t = document.querySelector('meta[name="graph-title"]');
      if (!t) {
        t = document.createElement("meta");
        t.name = "graph-title";
        document.head.appendChild(t);
      }
      t.content = document.title;
    }
    var b = bounds(g), pad = 20;
    oxGlobal = b.x0 - pad; oyGlobal = b.y0 - pad;
    W = Math.max(b.x1 - b.x0, 1) + 2 * pad;
    H = Math.max(b.y1 - b.y0, 1) + 2 * pad;
    colourEdges(g.edges);
    start(render(g, W, H));
  }).catch(function (e) {
    document.getElementById("root").innerHTML =
      '<div id="err"><strong>Could not load the graph</strong><div>' +
      esc(e && e.message ? e.message : e) + "</div></div>";
  });
})();
