#include "../../plugin_api.h"

#include <Windows.h>

#include <atomic>
#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>

static dbi_host_api g_host = {0};
static int g_have_host = 0;

static std::atomic<std::uint64_t> g_instruction_hits{0};
static std::atomic<std::uint64_t> g_branch_hits{0};
static std::atomic<std::uint32_t> g_process_starts{0};
static std::atomic<std::uint32_t> g_process_exits{0};

static volatile std::uint32_t g_patch_target = 0x12345678u;

static void host_log(const char* message) {
    if (message == nullptr) {
        return;
    }
    if (g_have_host && g_host.log != nullptr) {
        g_host.log(g_host.host_context, message);
    }
}

static void host_logf(const char* fmt, ...) {
    char buffer[1024]{};
    va_list args{};
    va_start(args, fmt);
    vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, fmt, args);
    va_end(args);
    host_log(buffer);
}

static int dbi_call on_load(const dbi_host_api* host) {
    if (host == nullptr) {
        return 0;
    }

    g_host = *host;
    g_have_host = 1;

    g_instruction_hits.store(0);
    g_branch_hits.store(0);
    g_process_starts.store(0);
    g_process_exits.store(0);
    g_patch_target = 0x12345678u;

    host_log("framework_showcase loaded");
    host_log("framework_showcase commands: showcase.help | showcase.ping | showcase.stats | showcase.patch_demo");
    return 1;
}

static void dbi_call on_unload() {
    host_logf(
        "framework_showcase unloaded: starts=%" PRIu32 " exits=%" PRIu32 " instruction_hits=%" PRIu64 " branch_hits=%" PRIu64,
        g_process_starts.load(),
        g_process_exits.load(),
        g_instruction_hits.load(),
        g_branch_hits.load());
    g_have_host = 0;
}

static void dbi_call on_process_start(std::uint32_t pid, const char* image_path_utf8) {
    const std::uint32_t starts = g_process_starts.fetch_add(1) + 1;
    host_logf(
        "framework_showcase: on_process_start pid=%" PRIu32 " image=%s starts=%" PRIu32,
        pid,
        image_path_utf8 ? image_path_utf8 : "<unknown>",
        starts);
}

static void dbi_call on_process_exit(std::uint32_t pid, std::uint32_t exit_code) {
    const std::uint32_t exits = g_process_exits.fetch_add(1) + 1;
    host_logf(
        "framework_showcase: on_process_exit pid=%" PRIu32 " code=%" PRIu32 " exits=%" PRIu32,
        pid,
        exit_code,
        exits);
}

static void dbi_call on_instruction_hit(std::uint32_t pid, std::uint64_t address) {
    const std::uint64_t hits = g_instruction_hits.fetch_add(1) + 1;
    if (hits <= 3 || (hits % 5000) == 0) {
        host_logf(
            "framework_showcase: on_instruction_hit pid=%" PRIu32 " addr=0x%016" PRIx64 " hits=%" PRIu64,
            pid,
            address,
            hits);
    }
}

static void dbi_call on_branch_hit(std::uint32_t pid, std::uint64_t address, const char* mnemonic, std::uint8_t length) {
    const std::uint64_t hits = g_branch_hits.fetch_add(1) + 1;
    if (hits <= 3 || (hits % 2000) == 0) {
        host_logf(
            "framework_showcase: on_branch_hit pid=%" PRIu32 " addr=0x%016" PRIx64 " mnemonic=%s len=%u hits=%" PRIu64,
            pid,
            address,
            mnemonic ? mnemonic : "?",
            static_cast<unsigned>(length),
            hits);
    }
}

static int run_patch_demo() {
    if (!g_have_host || g_host.apply_patch_bytes == nullptr || g_host.remove_patch == nullptr) {
        host_log("framework_showcase: patch API unavailable");
        return 1;
    }

    const std::uint32_t before = g_patch_target;
    const std::uint32_t demo_value = 0xDEADC0DEu;
    const std::uint8_t* demo_bytes = reinterpret_cast<const std::uint8_t*>(&demo_value);

    std::uint64_t patch_id = 0;
    const int applied = g_host.apply_patch_bytes(
        g_host.host_context,
        GetCurrentProcessId(),
        reinterpret_cast<std::uint64_t>(&g_patch_target),
        demo_bytes,
        sizeof(demo_value),
        &patch_id);

    if (!applied) {
        host_log("framework_showcase: apply_patch_bytes failed");
        return 1;
    }

    const std::uint32_t during = g_patch_target;
    const int removed = g_host.remove_patch(g_host.host_context, patch_id);
    const std::uint32_t after = g_patch_target;

    host_logf(
        "framework_showcase: patch_demo patch_id=%" PRIu64 " before=0x%08" PRIx32 " during=0x%08" PRIx32 " after=0x%08" PRIx32 " removed=%s",
        patch_id,
        before,
        during,
        after,
        removed ? "yes" : "no");

    return removed ? 0 : 1;
}

static int dbi_call on_command(const char* command, int argc, const char** argv, int* out_exit_code) {
    (void)argc;
    (void)argv;

    if (out_exit_code != nullptr) {
        *out_exit_code = 1;
    }
    if (command == nullptr) {
        return 0;
    }

    if (std::strcmp(command, "showcase.help") == 0) {
        host_log("framework_showcase commands:");
        host_log("  showcase.help");
        host_log("  showcase.ping");
        host_log("  showcase.stats");
        host_log("  showcase.patch_demo");
        if (out_exit_code != nullptr) {
            *out_exit_code = 0;
        }
        return 1;
    }

    if (std::strcmp(command, "showcase.ping") == 0) {
        host_log("framework_showcase: pong");
        if (out_exit_code != nullptr) {
            *out_exit_code = 0;
        }
        return 1;
    }

    if (std::strcmp(command, "showcase.stats") == 0) {
        host_logf(
            "framework_showcase: stats starts=%" PRIu32 " exits=%" PRIu32 " instruction_hits=%" PRIu64 " branch_hits=%" PRIu64 " patch_target=0x%08" PRIx32,
            g_process_starts.load(),
            g_process_exits.load(),
            g_instruction_hits.load(),
            g_branch_hits.load(),
            static_cast<std::uint32_t>(g_patch_target));
        if (out_exit_code != nullptr) {
            *out_exit_code = 0;
        }
        return 1;
    }

    if (std::strcmp(command, "showcase.patch_demo") == 0) {
        if (out_exit_code != nullptr) {
            *out_exit_code = run_patch_demo();
        }
        return 1;
    }

    return 0;
}

extern "C" __declspec(dllexport) int dbi_call dbi_plugin_init(dbi_plugin_api* out) {
    if (out == nullptr) {
        return 0;
    }

    out->version = dbi_plugin_api_version;
    out->name = "framework_showcase";
    out->on_load = &on_load;
    out->on_unload = &on_unload;
    out->on_instruction_hit = &on_instruction_hit;
    out->on_branch_hit = &on_branch_hit;
    out->plugin_version = "0.1.0";
    out->description = "Small showcase plugin for lifecycle hooks, hit callbacks, commands, and host patch API.";
    out->author = "DB toolkit";
    out->on_process_start = &on_process_start;
    out->on_process_exit = &on_process_exit;
    out->on_command = &on_command;
    return 1;
}

