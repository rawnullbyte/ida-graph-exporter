#ifdef __NT__
#include <windows.h>
#endif

#pragma warning(push )
#pragma warning(disable : 4244)
#pragma warning(disable : 4267)

#include <algorithm>

#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <registry.hpp>

#pragma warning(push)
#pragma warning(disable: 4996)
#include "json/json.h"
#pragma warning(pop)

#include "miniz.h"
#include "html_export.hpp"

#pragma warning( pop )

#define BB_COMP_THRESHOLD 0x40

/* IDA 9.2 renamed mutable_graph_t to interactive_graph_t (graph.hpp). */
#if IDA_SDK_VERSION >= 920
typedef interactive_graph_t ida_mutable_graph_t;
#else
typedef mutable_graph_t ida_mutable_graph_t;
#endif

struct plugin_ctx_t;

typedef struct font_params {
	char name[0x100];
	size_t name_len;
	unsigned int size;
	int flags;
#define FONT_PARAM_BOLD   (1 << 0)
#define FONT_PARAM_ITALIC (1 << 1)
} font_params_t;

static bool get_font_params(font_params_t *fparams)
{
#ifdef __NT__
	/* I have _no_ idea how portable this is. Still, it was the only way of obtaining
	 * the font properties of the disassembly view that I could find. */

	HKEY hk;
	DWORD tmp_len;
	DWORD tmp_val;

	if (!fparams) {
		return false;
	}

	memset(fparams, 0x00, sizeof(fparams));
	fparams->name_len = sizeof(fparams->name) - 1;
	fparams->size = UINT_MAX;

	if (RegOpenKeyEx(HKEY_CURRENT_USER, TEXT("Software\\Hex-Rays\\IDA\\Font\\Disassembly"),
		0, KEY_QUERY_VALUE, &hk) != ERROR_SUCCESS) {
		return false;
	}


	if (RegQueryValueEx(hk, TEXT("Name"), NULL, NULL, (PBYTE)fparams->name,
	                          (PDWORD)&fparams->name_len) != ERROR_SUCCESS) {
		RegCloseKey(hk);
		return false;
	}

	tmp_len = sizeof(fparams->size);
	if (RegQueryValueEx(hk, TEXT("Size"), NULL, NULL, (PBYTE)&fparams->size,
	                                    (PDWORD)&tmp_len) != ERROR_SUCCESS) {
		RegCloseKey(hk);
		return false;
	}

	tmp_len = sizeof(tmp_val);
	if (RegQueryValueEx(hk, TEXT("Bold"), NULL, NULL, (PBYTE)&tmp_val,
	                               (PDWORD)&tmp_len) != ERROR_SUCCESS) {
		RegCloseKey(hk);
		return false;
	}

	if (tmp_val == 1) {
		fparams->flags |= FONT_PARAM_BOLD;
	}

	tmp_len = sizeof(tmp_val);
	if (RegQueryValueEx(hk, TEXT("Italic"), NULL, NULL, (PBYTE)&tmp_val,
	                                 (PDWORD)&tmp_len) != ERROR_SUCCESS) {
		RegCloseKey(hk);
		return false;
	}

	if (tmp_val == 1) {
		fparams->flags |= FONT_PARAM_ITALIC;
	}

	RegCloseKey(hk);
	return true;
#else
	/* Let IDA's registry abstraction handle the platform specifics: it maps to
	 * the Windows registry on Windows and to ida.reg on Linux/macOS, so the
	 * same value names work everywhere. This mirrors the Windows path above
	 * (HKCU\Software\Hex-Rays\IDA\Font\Disassembly). Note the backslash: IDA's
	 * registry subkeys are backslash-separated (verified against IDA 9.3,
	 * where a forward slash silently reads nothing). If the key is absent we
	 * return false and the caller substitutes default values. */
	qstring font_name;

	if (!fparams) {
		return false;
	}

	memset(fparams, 0x00, sizeof(*fparams));
	fparams->name_len = sizeof(fparams->name) - 1;
	fparams->size = UINT_MAX;

	if (!reg_read_string(&font_name, "Name", "Font\\Disassembly")) {
		return false;
	}

	qstrncpy(fparams->name, font_name.c_str(), sizeof(fparams->name));
	fparams->name_len = font_name.length();

	/* Size and the style flags are missing from the registry until the user has
	 * customized the disassembly font, so fall back to IDA's defaults. */
	fparams->size = (unsigned int)reg_read_int("Size", 12, "Font\\Disassembly");

	if (reg_read_int("Bold", 0, "Font\\Disassembly") == 1) {
		fparams->flags |= FONT_PARAM_BOLD;
	}

	if (reg_read_int("Italic", 0, "Font\\Disassembly") == 1) {
		fparams->flags |= FONT_PARAM_ITALIC;
	}

	return true;
#endif
}

/* Small helper for compressing and base64 encoding a chunk of memory */
static bool base64_encode_memory(ea_t addr, ssize_t size, qstring *res, bool compress = true) {

	if (size <= 0)
		return false;

	size_t comp_size = 0;
	void *comp_data = NULL;
	void *raw_data = malloc(size);

	if (!raw_data)
		return false;

	get_bytes(raw_data, size, addr);

	if (compress) {
		comp_data = tdefl_compress_mem_to_heap(raw_data, size, &comp_size, 0x80 | TDEFL_WRITE_ZLIB_HEADER);
		if (!comp_data)
			return false;
	} else {
		comp_data = malloc(size);
		comp_size = size;
		memcpy(comp_data, raw_data, size);
	}

	free(raw_data);

	if (!base64_encode(res, comp_data, comp_size)) {
		free(comp_data);
		return false;
	}

	free(comp_data);
	return true;

}

/* Dumps function func to j_root. If graph is non-null, also dump basic block and edge coordinates. */
static bool export_function(Json::Value &j_func, func_t *func, ida_mutable_graph_t *graph = NULL)
{
	Json::Value j_bbs = Json::arrayValue;
	Json::Value j_edges = Json::arrayValue;
	size_t num_blocks = 0;
	qstring func_name = { 0 }, comp_mem = { 0 };
	qflow_chart_t fc;

	if (!j_func.empty() || !func)
		return false;

	/* Use create() rather than constructing a temporary and assigning it: the
	 * assignment relies on the implicitly generated operator= for a class with
	 * a vtable and graph members, whereas create() is the documented path. */
	fc.create("", func, BADADDR, BADADDR, 0);

	msg("GraphExporter: func=%p start=%#llx blocks=%d empty=%d gid=%#llx\n",
		(void *)func, (unsigned long long)func->start_ea, (int)fc.size(),
		(int)fc.empty(), (unsigned long long)(graph ? graph->gid : 0));

	if (fc.empty()) {
		msg("GraphExporter: FAIL fc.empty()\n");
		return false;
	}

	if (get_func_name(&func_name, func->start_ea) <= 0) {
		msg("GraphExporter: FAIL get_func_name()\n");
		return false;
	}

	/* Okay, if we got at least a function with a non-empty flow chart and a name,
	 * on any error we might encounter from now on, we fail gracefully by returning
	 * true but flagging the result as not valid */
	j_func["valid"] = false;
	j_func["error"] = "";

	j_func["has_graph"] = graph != NULL;
	j_func["name"] = func_name.c_str();
	j_func["start"] = (Json::UInt64)func->start_ea;
	j_func["end"] = (Json::UInt64)func->end_ea;
	j_func["bitness"] = get_func_bits(func);
	j_func["flags"] = (Json::UInt64)func->flags;
	j_func["color"] = func->color;
	j_func["frame_size"] = (Json::UInt64)func->frsize;
	j_func["frame_pointer_delta"] = (Json::Int64)func->fpd;

	if (!base64_encode_memory(func->start_ea, func->end_ea - func->start_ea, &comp_mem)) {
		j_func["error"] = "Error while compressing and base64 encoding function bytes.";
		return true;
	}

	j_func["bytes"] = comp_mem.c_str();

	if ((j_func["has_graph"] == true) && (fc.blocks.size() != graph->nodes.size())) {
		num_blocks = std::min(fc.blocks.size(), graph->nodes.size());
	} else {
		num_blocks = fc.blocks.size();
	}

	for (unsigned int i = 0; i < num_blocks; i++) {
		rect_t rect;
		qbasic_block_t bb = fc.blocks.at(i);
		text_t disasm_text;
		Json::Value j_cur_bb;
		Json::Value j_lines = Json::arrayValue;
		bool needs_compression = bb.end_ea - bb.start_ea > BB_COMP_THRESHOLD;

		if (j_func["has_graph"] == true) {
			rect = graph->nodes.at(i);
			//msg("%u %u %u %u %u %u\n", rect.top, rect.right, rect.left, rect.bottom, rect.width(), rect.height());
			j_cur_bb["left"] = rect.left;
			j_cur_bb["right"] = rect.right;
			j_cur_bb["top"] = rect.top;
			j_cur_bb["bottom"] = rect.bottom;
		} else {
			/* For the sanity of any person dealing with the final json, make graph-related
			 * attributes at least available and populate them with dummy values. */
			j_cur_bb["left"] = -1;
			j_cur_bb["right"] = -1;
			j_cur_bb["top"] = -1;
			j_cur_bb["bottom"] = -1;
		}

		j_cur_bb["addr_start"] = (Json::UInt64)bb.start_ea;
		j_cur_bb["addr_end"] = (Json::UInt64)bb.end_ea;
		j_cur_bb["id"] = i;
		j_cur_bb["compressed"] = needs_compression;

		if (!base64_encode_memory(bb.start_ea, bb.end_ea - bb.start_ea, &comp_mem, needs_compression)) {
			j_func["err"] = "Unable to dump basic block bytes.";
			return true;
		} else {
			j_cur_bb["bytes"] = comp_mem.c_str();
		}

		gen_disasm_text(disasm_text, bb.start_ea, bb.end_ea, false);

		for (twinline_t &line : disasm_text) {
			Json::Value j_cur_line;
			qstring line_b64;
			base64_encode(&line_b64, line.line.c_str(), line.line.size());
			j_cur_line["text"] = line_b64.c_str();
			j_cur_line["bg_color"] = line.bg_color;
			j_lines.append(j_cur_line);
		}
		j_cur_bb["disasm_lines"] = j_lines;

		for (int &j : bb.succ) {
			rect_t dstrect;
			edge_t e = edge_t(i, j);
			edge_info_t *einfo = NULL;
			char str_coords[0x100] = { 0 };
			Json::Value j_cur_edge_coords = Json::arrayValue;
			Json::Value j_cur_edge;

			j_cur_edge["source_id"] = i;
			j_cur_edge["dest_id"] = j;

			if (j_func["has_graph"] == false)
				continue;

			dstrect = graph->nodes.at(j);
			einfo = graph->get_edge(e);

			if (!einfo)
				continue;

			j_cur_edge["color"] = einfo->color;

			qsnprintf(str_coords, sizeof(str_coords) - 1, "%u %u", rect.left + einfo->srcoff, rect.bottom);
			j_cur_edge_coords.append(str_coords);
			for (point_t p : einfo->layout) {
				qsnprintf(str_coords, sizeof(str_coords), "%u %u", p.x, p.y);
				j_cur_edge_coords.append(str_coords);
			}
			qsnprintf(str_coords, sizeof(str_coords) - 1, "%u %u", dstrect.left + einfo->dstoff, dstrect.top);
			j_cur_edge_coords.append(str_coords);

			j_cur_edge["coords"] = j_cur_edge_coords;

			j_edges.append(j_cur_edge);
		}

		j_bbs.append(j_cur_bb);
	}

	j_func["basic_blocks"] = j_bbs;
	j_func["edges"] = j_edges;
	/* If we end up here, the exported json holds at least a non-trivial amount of information. */
	j_func["valid"] = true;

	return true;
}

static bool query_export_file_name(char *res, size_t res_len)
{
	std::string file_name;
	const char *user_input = NULL;

	try {
		/* The following is horrible, so let's wrap it in a try / catch until somebody
		* cleans it up. */
		file_name = get_path(PATH_TYPE_IDB);
		file_name = file_name.substr(0, file_name.rfind("." IDB_EXT)) + ".json";
#ifdef __NT__
		file_name = file_name.substr(file_name.find_last_of('\\'));
#else
		file_name = file_name.substr(file_name.find_last_of('/'));
#endif
	}
	catch (...) {
		file_name = "export.json";
	}

	qstrncpy(res, file_name.c_str(), res_len);

	if (batch)
		return true;

	user_input = ask_file(true, file_name.c_str(), "Please select export file name ...");

	if (!user_input)
		return false;

	qstrncpy(res, user_input, res_len);

	return true;
}

static bool json_dump_font_parameters(Json::Value &j_root)
{
	struct font_params fp = { 0 };
	bool result = true;

	if (!get_font_params(&fp)) {
		/* If we fail, print a warning and use robust defaults, even though the result
		 * will most likely look horrible. */
		memcpy(fp.name, "Courier", sizeof("Courier"));
		fp.name_len = strlen("Courier New");
		fp.size = 10;
		fp.flags = 0;
		result = false;

	}

	j_root["font_name"] = fp.name;
	j_root["font_size"] = fp.size;
	j_root["font_flags"] = fp.flags;

	return result;
}

bool idaapi export_current_graph(size_t)
{
	/* get_current_viewer() returns a TWidget*, which is not necessarily a graph
	 * viewer (it may be the disassembly view). IDA 9 requires the widget to be
	 * resolved to its graph viewer; casting the widget straight to
	 * graph_viewer_t* yields a bogus pointer whenever the focused widget is not
	 * a graph, and even when it is. */
	graph_viewer_t *gv = get_graph_viewer(get_current_viewer());
	ida_mutable_graph_t *g = gv ? get_viewer_graph(gv) : nullptr;
	func_t *func = NULL;
	char file_name[QMAXPATH] = { 0 };

	Json::Value j_funcs = Json::arrayValue;
	Json::Value j_root;
	Json::Value j_cur_func;

	if (!g) {
		/* Distinguish "no widget focused" from "widget is not a graph" from
		 * "the graph has no interactive layout yet" -- the original message
		 * lumped all three together, which made failures hard to diagnose. */
		if (!gv) {
			warning("No graph viewer found for the focused widget.\n"
				"Focus the graph window of a function (press spacebar on a "
				"function to open its graph view) and try again.\n");
		} else {
			warning("The focused graph viewer has no interactive graph yet.\n"
				"Try clicking inside the graph window once, then export again.\n");
		}
		return false;
	}

	if (!query_export_file_name(file_name, sizeof(file_name))) {
		return false;
	}

	if (!json_dump_font_parameters(j_root) && !batch) {
		warning("Failed to retrieve font parameters. Think about implementing or hack in correct values into the resulting json.\n");
	}

	if (!(func = get_func(g->gid))) {
		msg("GraphExporter: FAIL get_func(gid=%#llx)\n", (unsigned long long)g->gid);
		warning("Failed to retrieve current function.\n");
		return false;
	}

	msg("GraphExporter: gv=%p graph=%p gid=%#llx nodes=%d -> func %#llx\n",
		(void *)gv, (void *)g, (unsigned long long)g->gid,
		(int)g->nodes.size(), (unsigned long long)func->start_ea);

	show_wait_box("Exporting function at %#llx ...\n", (unsigned long long)func->start_ea);

	if (export_function(j_cur_func, func, g) == false) {
		hide_wait_box();
		msg("GraphExporter: FAIL export_function()\n");
		warning("Export failed. Did you focus a flow chart window when invoking the plugin?");
		return false;
	}

	if (j_cur_func["valid"] == 0) {
		msg("Information loss while exporting function at %#llx. Check the \"error\" field in the produced JSON.\n", (unsigned long long)func->start_ea);
	}

	j_funcs.append(j_cur_func);
	j_root["functions"] = j_funcs;

	/* Write the HTML page as well, so this single plugin produces the final
	 * deliverable and no separate conversion step is needed. */
	qstring html_name = file_name;
	size_t dot = html_name.rfind('.');
	if (dot != qstring::npos)
		html_name.resize(dot);
	html_name += ".html";

	if (!export_graph_html(j_root, html_name.c_str()))
		warning("Failed to write %s\n", html_name.c_str());

	hide_wait_box();

	return true;

}

#if IDA_SDK_VERSION <= 740

//-------------------------------------------------------------------------
int idaapi init(void)
{
	return PLUGIN_KEEP;
}

#else
struct plugin_ctx_t : public plugmod_t
{
	virtual bool idaapi run(size_t) override;
};

bool idaapi plugin_ctx_t::run(size_t s) {
	return export_current_graph(s);
}

static plugmod_t *idaapi init()
{
	if (!is_idaq())
		return nullptr;
	return new plugin_ctx_t;
}
#endif

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
#if IDA_SDK_VERSION <= 740
	0,                    // plugin flags
#else
	PLUGIN_MULTI,         // The plugin can work with multiple idbs in parallel
#endif
	init,                 // initialize
	NULL,                 // terminate. this pointer may be NULL.
#if IDA_SDK_VERSION <= 740
	export_current_graph, // invoke plugin
#else
	NULL,                 // functionality exported via plugmod_t now
#endif
	NULL,
	NULL,
	"Graph Exporter",
	"Alt+G",
};
