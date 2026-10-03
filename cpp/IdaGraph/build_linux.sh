#!/usr/bin/env bash
#
# Build the IDA Graph Exporter plugin for 64-bit Linux (IdaGraph.so).
#
# Requires the IDA SDK: https://github.com/HexRaysSA/ida-sdk
# Point IDASDK at the SDK root (the directory holding include/ and lib/), or
# pass it as the second argument. Both the ida-sdk repository layout (include/
# and lib/ under src/) and a plain SDK extraction are accepted.
#
# Usage: ./build_linux.sh [output-dir] [sdk-dir] [sdk-ref]
#
# The optional sdk-ref argument (e.g. v9.4.0-sdk.1) is only used to fetch the
# SDK when sdk-dir is missing or does not contain one.

set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-$SRC_DIR/build}"
SDK_DIR="${2:-${IDASDK:-}}"
SDK_REF="${3:-}"

SDK_REPO="${IDA_SDK_REPO:-https://github.com/HexRaysSA/ida-sdk.git}"

# The SDK's headers/libraries live under src/ in the ida-sdk repository.
if [[ -n "$SDK_DIR" && -d "$SDK_DIR/src/include" ]]; then
    SDK_DIR="$SDK_DIR/src"
fi

if [[ -z "$SDK_DIR" || ! -f "$SDK_DIR/include/ida.hpp" ]]; then
    if [[ -n "$SDK_REF" ]]; then
        SDK_DIR="$OUT_DIR/ida-sdk"
        echo "==> Fetching IDA SDK ($SDK_REF)"
        rm -rf "$SDK_DIR"
        git clone --depth 1 --branch "$SDK_REF" "$SDK_REPO" "$SDK_DIR"
        SDK_DIR="$SDK_DIR/src"
    else
        echo "error: no IDA SDK found." >&2
        echo "       Set IDASDK to the SDK root, pass it as the 2nd argument, or" >&2
        echo "       pass an SDK ref as the 3rd argument to fetch one." >&2
        exit 1
    fi
fi

if [[ ! -f "$SDK_DIR/include/ida.hpp" ]]; then
    echo "error: '$SDK_DIR' does not look like an IDA SDK (missing include/ida.hpp)." >&2
    exit 1
fi

LIB_DIR="$SDK_DIR/lib/x64_linux_64"
if [[ ! -f "$LIB_DIR/libida.so" ]]; then
    echo "error: missing Linux x86_64 stubs in '$LIB_DIR'." >&2
    echo "       The public IDA SDK only ships 64-bit Linux libraries; 32-bit" >&2
    echo "       Linux plugins cannot be linked against it." >&2
    exit 1
fi

CXX="${CXX:-g++}"
CC="${CC:-gcc}"

for tool in "$CXX" "$CC"; do
    command -v "$tool" >/dev/null 2>&1 || { echo "error: '$tool' not found." >&2; exit 1; }
done

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

# -ffile-prefix-map keeps absolute build paths out of the binary, so artifacts
# built in a different directory (or on a CI runner) come out identical.
#
# __EA64__ and __X64__ are mandatory for 64-bit IDA and are NOT inferred by the
# SDK: they control sizeof(ea_t) and the IDP_INTERFACE_VERSION-visible layouts.
# Without them ea_t is 4 bytes, func_t is 120 bytes instead of 144 (so every
# func_t field is read at the wrong offset) and BADADDR is 0xffffffff, which
# makes qflow_chart_t() produce zero blocks. The SDK's own makefile builds with
# "__EA64__=1 __X64__=1"; see src/makefile and src/allmake.mak.
MAP_FLAGS=(-ffile-prefix-map="$SRC_DIR"=. -ffile-prefix-map="$SDK_DIR"=idasdk)
ABI_FLAGS=(-D__EA64__ -D__X64__)
CXXFLAGS=(-std=c++17 -fPIC -O2 "${ABI_FLAGS[@]}" "${MAP_FLAGS[@]}")
CFLAGS=(-fPIC -O2 "${ABI_FLAGS[@]}" "${MAP_FLAGS[@]}")
# The plugin source builds warning-free; third-party sources are silenced below.
# -Wno-unknown-pragmas covers the MSVC #pragma warning blocks in the source,
# which GCC correctly ignores.
PLUGIN_WARNINGS=(-Wall -Wno-unknown-pragmas -Wno-deprecated-declarations)

echo "==> Plugin source"
"$CXX" -c "${CXXFLAGS[@]}" "${PLUGIN_WARNINGS[@]}" -isystem "$SDK_DIR/include" -I"$SRC_DIR" \
    "$SRC_DIR/ida_graph.cpp" -o "$OUT_DIR/ida_graph.o"

echo "==> HTML export"
"$CXX" -c "${CXXFLAGS[@]}" "${PLUGIN_WARNINGS[@]}" -isystem "$SDK_DIR/include" -I"$SRC_DIR" \
    "$SRC_DIR/html_export.cpp" -o "$OUT_DIR/html_export.o"

echo "==> jsoncpp (vendored)"
"$CXX" -c "${CXXFLAGS[@]}" -w -I"$SRC_DIR" "$SRC_DIR/jsoncpp.cpp" -o "$OUT_DIR/jsoncpp.o"

echo "==> miniz (vendored)"
"$CC" -c "${CFLAGS[@]}" -w -I"$SRC_DIR" "$SRC_DIR/miniz.c" -o "$OUT_DIR/miniz.o"

echo "==> Linking IdaGraph.so"
"$CXX" -shared -o "$OUT_DIR/IdaGraph.so" \
    "$OUT_DIR/ida_graph.o" "$OUT_DIR/html_export.o" \
    "$OUT_DIR/jsoncpp.o" "$OUT_DIR/miniz.o" \
    -L"$LIB_DIR" -l:libida.so

echo
echo "Built: $OUT_DIR/IdaGraph.so"
echo "Copy it into the 'plugins' directory of a 64-bit Linux IDA Pro installation."
