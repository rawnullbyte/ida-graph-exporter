# IDA Graph Exporter

## What?

Plugin for IDA Pro that exports a function as rendered in the graph view to a
single self-contained interactive HTML page. The plugin reads the currently
focused graph view and writes the page directly, so there is no conversion step
and no other tool to install.

The plugin reads the currently focused graph view and writes a small HTML file
containing a single iframe. The viewer itself is a static page hosted on GitHub
Pages (see `web/`), so the file does not need to be regenerated when the viewer
changes — every export points at the same current viewer.

The graph travels with the export in the iframe URL's fragment, compressed and
base64url-encoded. A URL fragment is never sent to a server, so the graph data
stays in the reader's browser and never leaves their machine; the export still
opens from `file://`. The hosted viewer shows IDA's own layout: basic blocks are
positioned divs at the coordinates IDA exported, the edges are SVG paths
following the routed polylines, and the disassembly keeps IDA's colours. The
whole drawing sits in one transformed layer, so the edges and their arrowheads
scale with the zoom. Drag to pan, scroll to zoom.

Because the viewer runs inside an iframe, its toolbar and full-page styles
cannot cover a surrounding page — which is what makes the export safe to embed
in a Ghost HTML card. The iframe defaults to 70vh tall (at least 480px); adjust
its `height` style in the exported file to change that.

## Hosting the viewer

`.github/workflows/pages.yml` publishes `web/` to GitHub Pages whenever the
viewer or that workflow changes. The account's user site carries the custom
domain `nullbyte.rip`, so the project site is served under it at:

```
https://nullbyte.rip/ida-graph-exporter/viewer.html
```

The exporter hard-codes that URL in `IDA_GRAPH_VIEWER_URL`
(`cpp/IdaGraph/html_export.cpp`). Forks can override it at build time:

```bash
CXXFLAGS="-DIDA_GRAPH_VIEWER_URL='\"https://example.com/viewer.html\"'" ./cpp/IdaGraph/build_linux.sh
```

Note that Pages for this repository uses `build_type: workflow`, which is what
`deploy-pages` requires, rather than a branch-folder source.

The native code ships (amalgamated) copies of [miniz 3.0.2](https://github.com/richgel999/miniz)
and [jsoncpp 1.9.5](https://github.com/open-source-parsers/jsoncpp) for
compression and JSON serialization.

## How?

1. Compile the source in this repository (you need the Hex-Rays SDK to do that),
   or build the Linux plugin as described below.
2. Copy the plugin (`IdaGraph.so` on Linux) into the `plugins` directory of your
   local IDA Pro installation and reload IDA.
3. Open the control flow graph that is to be exported in a graph viewer tab and
   run `Edit -> Plugins -> Graph Exporter` (`Alt+G`).
4. Pick an output file name. The `.html` page is written there.

## Building for Linux

The plugin builds as a single 64-bit `IdaGraph.so`. It requires the
[IDA SDK](https://github.com/HexRaysSA/ida-sdk) and a C++17 compiler; the
vendored jsoncpp and miniz sources are compiled in, so there are no other
dependencies.

```bash
# Uses IDASDK if set, otherwise fetches the pinned SDK revision.
./cpp/IdaGraph/build_linux.sh [output-dir] [sdk-dir] [sdk-ref]
```

The resulting `IdaGraph.so` goes into the `plugins` directory of a 64-bit Linux
IDA Pro installation. The public SDK only ships 64-bit Linux libraries, so a
32-bit Linux plugin cannot be linked against it.

### SDK version and IDA compatibility

The build is pinned to SDK `v9.3.0-sdk.3` (see `IDA_SDK_REF` in the workflow)
rather than the newest SDK. IDA 9.4 renamed `get_func_bitness()` to
`get_func_bitness_ea()`, so a plugin linked against SDK 9.4 **fails to load in
IDA 9.3** with an unresolved symbol. IDA 9.4 and newer still export the older
`get_func_bitness`, so a plugin built against SDK 9.3 loads on 9.3 and newer.
Building against the newest SDK is therefore not the widest-compatibility
choice; the workflow's "Check IDA symbols resolve" step guards this.

`.github/workflows/linux.yml` runs the same script and attaches `IdaGraph.so` to
each workflow run as the `IdaGraph-linux-x86_64` artifact.

## Example

Screenshot of some function taken from an `/usr/bin/id` binary:

![Screenshot of Control Flow Graph](example/id_screenshot.png)

The earlier SVG-based example output is still in `example/` for reference:
[`id.json.pdf.svg`](example/id.json.pdf.svg) and its
[PDF rendition](example/id.json.pdf).
