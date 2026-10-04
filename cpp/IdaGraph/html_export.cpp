// Writes the exported graph as a small HTML file containing one iframe.
//
// The viewer itself is a static page served from the project's GitHub Pages
// site (see web/). Only the graph travels with the export, carried in the
// iframe URL's fragment: fragments are never sent to the server, so the graph
// data stays in the reader's browser and the page works from file:// as well.
//
// The payload is minified, stripped of the raw byte blobs the viewer never
// reads, flate-compressed, then base64url-encoded. On a 131-block function
// that is roughly 19 KB of JSON down to a 2 KB fragment.
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

#include "json/json.h"
#include "miniz.h"
#include "html_export.hpp"

// Where the hosted viewer lives. Overridable at build time for forks.
//
// The account's user site carries the custom domain nullbyte.rip, so project
// sites are served beneath it: the github.io project path redirects here.
#ifndef IDA_GRAPH_VIEWER_URL
#define IDA_GRAPH_VIEWER_URL \
    "https://nullbyte.rip/ida-graph-exporter/viewer.html"
#endif

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

// base64url: the fragment has to survive being pasted into HTML, so the
// characters that would need escaping (+, /) are replaced.
static std::string base64url_encode(const unsigned char *data, size_t len) {
    static const char *T =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    size_t i = 0;
    while (i + 2 < len) {
        unsigned n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(T[(n >> 18) & 63]);
        out.push_back(T[(n >> 12) & 63]);
        out.push_back(T[(n >> 6) & 63]);
        out.push_back(T[n & 63]);
        i += 3;
    }
    if (i + 1 == len) {
        unsigned n = data[i] << 16;
        out.push_back(T[(n >> 18) & 63]);
        out.push_back(T[(n >> 12) & 63]);
    } else if (i + 2 == len) {
        unsigned n = (data[i] << 16) | (data[i + 1] << 8);
        out.push_back(T[(n >> 18) & 63]);
        out.push_back(T[(n >> 12) & 63]);
        out.push_back(T[(n >> 6) & 63]);
    }
    return out;
}

bool export_graph_html(const Json::Value &root, const char *filename)
{
    if (!root.isMember("functions") || root["functions"].empty())
        return false;

    const Json::Value &g = root["functions"][0];
    std::string title = esc(g["name"].asString()) + " - graph";

    /* The viewer renders from geometry and disassembly text; the base64 byte
     * blobs exist for other consumers and are pure weight here. On a large
     * function they are a fifth of the payload. */
    Json::Value lean = root;
    Json::Value &lg = lean["functions"][0];
    lg.removeMember("bytes");
    for (auto &b : lg["basic_blocks"])
        b.removeMember("bytes");

    Json::StreamWriterBuilder wb;
    wb.settings_["indentation"] = "";
    wb.settings_["commentStyle"] = "None";
    std::string json = Json::writeString(wb, lean);

    /* zlib-wrapped deflate, which is what the browser's
     * DecompressionStream("deflate") expects. */
    size_t comp_len = 0;
    void *comp = tdefl_compress_mem_to_heap(json.data(), json.size(), &comp_len,
                                            0x80 | TDEFL_WRITE_ZLIB_HEADER);
    if (!comp)
        return false;
    std::string fragment = base64url_encode((const unsigned char *)comp, comp_len);
    mz_free(comp);

    std::ofstream file(filename, std::ios::binary);
    if (!file)
        return false;

    file << "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
         << "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
         << "<title>" << title << "</title></head>\n<body style=\"margin:0\">\n"
         << "<iframe title=\"" << title << "\" loading=\"lazy\" allowfullscreen\n"
         << " style=\"display:block;width:100%;height:70vh;min-height:480px;"
            "border:0;border-radius:6px\"\n"
         << " src=\"" << IDA_GRAPH_VIEWER_URL << "#d=" << fragment << "\">"
         << "</iframe>\n</body></html>\n";

    return file.good();
}
