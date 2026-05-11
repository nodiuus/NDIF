// Sample plugin DLL: logs instruction hits and shows host patch API usage.
//
// Build as a DLL project and add `DBI/plugin_api.h` to the include path.

#include "../../plugin_api.h"

#include <stdint.h>
#include <string.h>

static db_host_api g_host = {0};
static int g_have_host = 0;
static uint64_t g_hits = 0;

static int db_call on_load(const db_host_api* host) {
    if (!host) {
        return 0;
    }

    g_host = *host; // copy; do not retain a pointer to stack memory
    g_have_host = 1;
    g_hits = 0;
    if (g_have_host && g_host.log) {
        g_host.log(g_host.host_context, "sample_hit_logger loaded");
    }
    return 1;
}

static void db_call on_unload() {
    if (g_have_host && g_host.log) {
        g_host.log(g_host.host_context, "sample_hit_logger unloaded");
    }
    g_have_host = 0;
}

static void db_call on_process_start(uint32_t pid, const char* image_path_utf8) {
    (void)pid;
    if (g_have_host && g_host.log) {
        g_host.log(g_host.host_context, image_path_utf8 ? "sample_hit_logger: process start" : "sample_hit_logger: process start (no path)");
    }
}

static void db_call on_process_exit(uint32_t pid, uint32_t exit_code) {
    (void)pid;
    (void)exit_code;
    if (g_have_host && g_host.log) {
        g_host.log(g_host.host_context, "sample_hit_logger: process exit");
    }
}

static void db_call on_instruction_hit(uint32_t pid, uint64_t address) {
    (void)pid;
    (void)address;

    ++g_hits;
    if (g_have_host && g_host.log && (g_hits <= 5 || (g_hits % 1000) == 0)) {
        g_host.log(g_host.host_context, "sample_hit_logger: instruction hit");
    }
}

static void db_call on_branch_hit(uint32_t pid, uint64_t address, const char* mnemonic, uint8_t length) {
    (void)pid;
    (void)address;
    (void)mnemonic;
    (void)length;
}

static int db_call on_command(const char* command, int argc, const char** argv, int* out_exit_code) {
    (void)argc;
    (void)argv;

    if (out_exit_code) {
        *out_exit_code = 1;
    }

    if (!command) {
        return 0;
    }

    // Example: `DBI.exe -c sample.ping`
    if (strcmp(command, "sample.ping") == 0) {
        if (g_have_host && g_host.log) {
            g_host.log(g_host.host_context, "sample_hit_logger: pong");
        }
        if (out_exit_code) {
            *out_exit_code = 0;
        }
        return 1;
    }

    return 0;
}

extern "C" __declspec(dllexport) int db_call db_plugin_init(db_plugin_api* out) {
    if (!out) {
        return 0;
    }
    out->version = db_plugin_api_version;
    out->name = "sample_hit_logger";
    out->on_load = &on_load;
    out->on_unload = &on_unload;
    out->on_instruction_hit = &on_instruction_hit;
    out->on_branch_hit = &on_branch_hit;
    out->plugin_version = "0.1.0";
    out->description = "Logs instruction hits and demonstrates the command/lifecycle hooks.";
    out->author = "DBI sample";
    out->on_process_start = &on_process_start;
    out->on_process_exit = &on_process_exit;
    out->on_command = &on_command;
    return 1;
}
