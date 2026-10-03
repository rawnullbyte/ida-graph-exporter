# IDA Graph Exporter

## What?

Plugin for IDA Pro that allows to export a function as rendered in the graph view to a vectorized SVG or an interactive HTML page. The native plugin retrieves all relevant information from the currently focused graph view and stores them into a JSON. The JSON is then processed by `json2svg.py` to produce an SVG and/or a self-contained HTML viewer. Compiled versions of the plugin for IDA Versions 7.0 to 8.2 can be found on the [Release page](https://github.com/kirschju/ida-graph-exporter/releases).

The native code ships (amalgamated) copies of [miniz 3.0.2](https://github.com/richgel999/miniz) and [jsoncpp 1.9.5](https://github.com/open-source-parsers/jsoncpp) for compression and JSON serialization. The python script converting JSON to SVG needs [svgwrite](https://pypi.org/project/svgwrite/) installed.

## How?

1. Compile the source in this repository (you need the Hex-Rays SDK to do that) or download a precompiled plugin matching (closely) your IDA Pro version from the
[Release page](https://github.com/kirschju/ida-graph-exporter/releases).
2. Copy both `IdaGraph.dll` and `IdaGraph64.dll` into the `plugins` directory of your local IDA Pro installation and reload IDA.
3. Open the control flow graph that is to be exported in a graph viewer tab and export it to JSON via `Edit -> Plugins -> Graph Exporter`.
4. Convert the JSON with `json2svg.py <output.json> [svg|html|all]`. With no
format argument both an `.svg` and a self-contained, interactive `.html` are
written next to the input.
5. Optional: To convert the SVG to PDF, I use `rsvg-convert -f pdf -o <output.pdf> <input.svg>`

## Output formats

* **SVG** (`<input>.svg`) — the vectorized graph, sized to the exported
  coordinates. Suitable for PDF conversion or further editing.
* **HTML** (`<input>.html`) — the same graph as a single interactive page with
  drag-to-pan and wheel-to-zoom. Everything is inlined, so it renders offline
  with no CDN or network access.

## Building for Linux

On Linux, the plugin is built as a single 64-bit `IdaGraph.so`. It requires the
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

Exported SVG:

![Exported SVG showing Control Flow Graph](example/id.json.pdf.svg)

Converting from SVG to [PDF](example/id.json.pdf):

```bash
rsvg-convert -f pdf -o id.json.pdf id.json.pdf.svg
```
