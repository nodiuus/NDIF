#pragma once

// Stable C ABI for DBI plugins.

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ABI compatibility policy:
// - Always append fields to structs (never reorder/remove).
// - Host must accept older plugin versions (<= host version).
#define dbi_plugin_api_version 4u

#if defined(_MSC_VER)
    #if defined(_M_X64)
        #define dbi_call __fastcall
    #else
        #define dbi_call __cdecl
    #endif
#else
    #define dbi_call
#endif

typedef struct dbi_host_api {
    uint32_t version;
    void* host_context;

    void(dbi_call* log)(void* host_context, const char* message);

    // Optional patch helpers (host-managed patch ids). plugins can ignore these.
    // Host may restrict patching to self-only.
    int(dbi_call* apply_patch_bytes)(
        void* host_context,
        uint32_t pid,
        uint64_t address,
        const uint8_t* bytes,
        size_t size,
        uint64_t* out_patch_id);

    int(dbi_call* remove_patch)(
        void* host_context,
        uint64_t patch_id);

    // Reserved for future expansion (keep ABI stable).
    void* reserved1;
    void* reserved2;
} dbi_host_api;

typedef struct dbi_plugin_api {
    uint32_t version;
    const char* name;

    // Host guarantees `host` points to stable memory for the plugin's lifetime.
    // plugins may still prefer to copy *host locally.
    int(dbi_call* on_load)(const dbi_host_api* host);
    void(dbi_call* on_unload)();

    // Called on every breakpoint hit that the host instrumentor observes.
    void(dbi_call* on_instruction_hit)(uint32_t pid, uint64_t address);

    // Optional metadata.
    const char* plugin_version;
    const char* description;
    const char* author;

    // Optional lifecycle events (best-effort; not all modes provide all events).
    void(dbi_call* on_process_start)(uint32_t pid, const char* image_path_utf8);
    void(dbi_call* on_process_exit)(uint32_t pid, uint32_t exit_code);

    // Optional CLI/command hook: return 1 if handled, 0 otherwise.
    // If handled, set *out_exit_code (0 means success).
    int(dbi_call* on_command)(const char* command, int argc, const char** argv, int* out_exit_code);

    // Called when the hit instruction is a control-flow transfer (branch/call/ret/etc).
    // `mnemonic` points to a host-owned static string (do not free).
    void(dbi_call* on_branch_hit)(uint32_t pid, uint64_t address, const char* mnemonic, uint8_t length);

    // Optional GUI/config metadata. Expected format is a UTF-8 JSON array of objects:
    // [{ "name":"events_path", "label":"Events Path", "type":"path", "default":"..." }]
    const char* options_json;

    // Optional configuration hook. Arguments are host-owned UTF-8 strings, commonly `key=value`.
    // Return 1 on success, 0 on invalid configuration.
    int(dbi_call* on_configure)(int argc, const char** argv);
} dbi_plugin_api;

typedef int(dbi_call* dbi_plugin_init_fn)(dbi_plugin_api* out_plugin_api);

// Exported by plugin DLLs:
//   extern "C" __declspec(dllexport) int dbi_plugin_init(dbi_plugin_api* out);

#ifdef __cplusplus
} // extern "C"
#endif
