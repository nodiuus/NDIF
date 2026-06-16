#pragma once

#include "plugin_api.h"

#include <Windows.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

class plugin_manager {
public:
    struct plugin_info {
        std::string name{};
        std::string plugin_version{};
        std::string description{};
        std::string author{};
        std::string options_json{};
        std::wstring path{};
        std::uint32_t api_version{0};
    };

    plugin_manager();
    ~plugin_manager();

    plugin_manager(const plugin_manager&) = delete;
    plugin_manager& operator=(const plugin_manager&) = delete;

    bool load_from_directory(const std::wstring& directory);
    bool load_plugin(const std::wstring& dll_path);
    void unload_all();

    void on_process_start(std::uint32_t pid, const std::wstring& image_path);
    void on_process_exit(std::uint32_t pid, std::uint32_t exit_code);
    void on_instruction_hit(std::uint32_t pid, std::uint64_t address);
    void on_branch_hit(std::uint32_t pid, std::uint64_t address, const char* mnemonic, std::uint8_t length);

    std::vector<plugin_info> list_loaded_plugins() const;

    bool dispatch_command(const std::string& command, const std::vector<std::string>& args, int& out_exit_code);
    bool configure_loaded_plugins(const std::vector<std::string>& args);
    void set_log_callback(std::function<void(const char*)> callback);

    // Host patch service exposed to plugins via dbi_host_api.
    bool apply_patch_bytes(std::uint32_t pid, std::uint64_t address, const std::uint8_t* bytes, std::size_t size, std::uint64_t& out_patch_id);
    bool remove_patch(std::uint64_t patch_id);

private:
    struct plugin_entry {
        HMODULE module{nullptr};
        std::wstring path{};
        dbi_plugin_api api{};
        bool loaded{false};
    };

    struct patch_binding {
        std::uint64_t local_patch_id{0};
    };

    static void dbi_call host_log(void* host_context, const char* message);
    static int dbi_call host_apply_patch_bytes(void* host_context, uint32_t pid, uint64_t address, const uint8_t* bytes, size_t size, uint64_t* out_patch_id);
    static int dbi_call host_remove_patch(void* host_context, uint64_t patch_id);

    dbi_host_api build_host_api();
    void close_plugin(plugin_entry& plugin);
    void emit_log(const char* message) const;

    mutable std::mutex lock_{};
    std::vector<plugin_entry> plugins_{};
    dbi_host_api host_api_{}; // stable storage for plugins to keep a pointer to
    std::function<void(const char*)> log_callback_{};

    // Host-managed patch ids so plugins can remove patches later.
    std::uint64_t next_host_patch_id_{1};
    std::unordered_map<std::uint64_t, patch_binding> host_patch_map_{};

    // Host-owned patcher (stored as opaque pointer to avoid including live_patch headers here).
    struct patcher_entry;
    std::unique_ptr<patcher_entry> self_patcher_{};
};
