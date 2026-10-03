#ifndef HTML_EXPORT_HPP
#define HTML_EXPORT_HPP

#include "json/json.h"

// Render an exported graph as a self-contained interactive HTML page.
// root is the same tree the plugin hands to the JSON writer: {functions:[...]}.
// Returns false if the tree has no function or the file cannot be opened.
bool export_graph_html(const Json::Value &root, const char *filename);

#endif
