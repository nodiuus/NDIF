#include "plugin_manager.h"

#include "live_patch_framework.h"

#include <Windows.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

struct plugin_manager::patcher_entry {
    std::unique_ptr<live_patch_framework> patcher{};
};

plugin_manager::plugin_manager() {
    host_api_ = build_host_api();
}

plugin_manager::~plugin_manager() {
    unload_all();
}

namespace {
std::string wide_to_utf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) {
        return {};
    }

    std::string result(static_cast<std::size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), size - 1, nullptr, nullptr);
    return result;
}

void log_plugin_fault(const char* message) {
    if (message == nullptr) {
        return;
    }

    std::cerr << "[plugin] " << message << "\n";
    OutputDebugStringA(message);
    OutputDebugStringA("\n");
}

int safe_call_on_load(int(dbi_call* fn)(const dbi_host_api*), const dbi_host_api* host) {
    if (fn == nullptr) {
        return 0;
    }

    __try {
        return fn(host);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_plugin_fault("plugin fault in on_load");
        return 0;
    }
}

void safe_call_on_unload(void(dbi_call* fn)()) {
    if (fn == nullptr) {
        return;
    }

    __try {
        fn();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_plugin_fault("plugin fault in on_unload (ignored)");
    }
}

void safe_call_on_process_start(void(dbi_call* fn)(uint32_t, const char*), uint32_t pid, const char* image_path_utf8) {
    if (fn == nullptr) {
        return;
    }

    __try {
        fn(pid, image_path_utf8);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_plugin_fault("plugin fault in on_process_start (ignored)");
    }
}

void safe_call_on_process_exit(void(dbi_call* fn)(uint32_t, uint32_t), uint32_t pid, uint32_t exit_code) {
    if (fn == nullptr) {
        return;
    }

    __try {
        fn(pid, exit_code);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_plugin_fault("plugin fault in on_process_exit (ignored)");
    }
}

void safe_call_on_instruction_hit(void(dbi_call* fn)(uint32_t, uint64_t), uint32_t pid, uint64_t address) {
    if (fn == nullptr) {
        return;
    }

    __try {
        fn(pid, address);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_plugin_fault("plugin fault in on_instruction_hit (ignored)");
    }
}

void safe_call_on_branch_hit(void(dbi_call* fn)(uint32_t, uint64_t, const char*, uint8_t), uint32_t pid, uint64_t address, const char* mnemonic, uint8_t length) {
    if (fn == nullptr) {
        return;
    }

    __try {
        fn(pid, address, mnemonic, length);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_plugin_fault("plugin fault in on_branch_hit (ignored)");
    }
}

int safe_call_on_command(int(dbi_call* fn)(const char*, int, const char**, int*), const char* command, int argc, const char** argv, int* out_exit_code) {
    if (fn == nullptr) {
        return 0;
    }

    __try {
        return fn(command, argc, argv, out_exit_code);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_plugin_fault("plugin fault in on_command (ignored)");
        return 0;
    }
}

int safe_call_on_configure(int(dbi_call* fn)(int, const char**), int argc, const char** argv) {
    if (fn == nullptr) {
        return 1;
    }

    __try {
        return fn(argc, argv);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_plugin_fault("plugin fault in on_configure (ignored)");
        return 0;
    }
}

void safe_free_library(HMODULE module) {
    if (module == nullptr) {
        return;
    }

    __try {
        FreeLibrary(module);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_plugin_fault("plugin fault during FreeLibrary (ignored)");
    }
}
} // namespace

void plugin_manager::host_log(void* host_context, const char* message) {
    (void)host_context;
    if (message == nullptr) {
        return;
    }

    std::cerr << "[plugin] " << message << "\n";
    OutputDebugStringA(message);
    OutputDebugStringA("\n");
}

int plugin_manager::host_apply_patch_bytes(void* host_context, uint32_t pid, uint64_t address, const uint8_t* bytes, size_t size, uint64_t* out_patch_id) {
    if (host_context == nullptr || out_patch_id == nullptr) {
        return 0;
    }

    auto* self = reinterpret_cast<plugin_manager*>(host_context);
    std::uint64_t id = 0;
    const bool ok = self->apply_patch_bytes(pid, address, bytes, size, id);
    if (ok) {
        *out_patch_id = id;
        return 1;
    }
    return 0;
}

int plugin_manager::host_remove_patch(void* host_context, uint64_t patch_id) {
    if (host_context == nullptr) {
        return 0;
    }

    auto* self = reinterpret_cast<plugin_manager*>(host_context);
    return self->remove_patch(patch_id) ? 1 : 0;
}

dbi_host_api plugin_manager::build_host_api() {
    dbi_host_api host{};
    host.version = dbi_plugin_api_version;
    host.host_context = this;
    host.log = &plugin_manager::host_log;
    host.apply_patch_bytes = &plugin_manager::host_apply_patch_bytes;
    host.remove_patch = &plugin_manager::host_remove_patch;
    host.reserved1 = nullptr;
    host.reserved2 = nullptr;
    return host;
}

bool plugin_manager::load_from_directory(const std::wstring& directory) {
    const std::wstring pattern = directory + L"\\*.dll";

    WIN32_FIND_DATAW find_data{};
    HANDLE find = FindFirstFileW(pattern.c_str(), &find_data);
    if (find == INVALID_HANDLE_VALUE) {
        return false;
    }

    std::vector<std::wstring> dlls{};
    do {
        if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            continue;
        }

        const std::wstring path = directory + L"\\" + find_data.cFileName;
        dlls.push_back(path);
    } while (FindNextFileW(find, &find_data));

    FindClose(find);
    for (const std::wstring& path : dlls) {
        load_plugin(path);
    }
    return true;
}

bool plugin_manager::load_plugin(const std::wstring& dll_path) {
    HMODULE module = LoadLibraryExW(dll_path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (module == nullptr) {
        module = LoadLibraryW(dll_path.c_str());
    }
    if (module == nullptr) {
        return false;
    }

    {
        std::lock_guard<std::mutex> guard(lock_);
        const auto duplicate = std::find_if(plugins_.begin(), plugins_.end(), [&](const plugin_entry& plugin) {
            return plugin.loaded && plugin.module == module;
        });
        if (duplicate != plugins_.end()) {
            safe_free_library(module);
            return true;
        }
    }

    auto init_fn = reinterpret_cast<dbi_plugin_init_fn>(GetProcAddress(module, "dbi_plugin_init"));
    if (init_fn == nullptr) {
        safe_free_library(module);
        return false;
    }

    dbi_plugin_api api{};
    api.version = 0;

    if (!init_fn(&api) || api.version == 0 || api.version > dbi_plugin_api_version || api.name == nullptr) {
        safe_free_library(module);
        return false;
    }

    plugin_entry plugin{};
    plugin.module = module;
    plugin.path = dll_path;
    plugin.api = api;
    plugin.loaded = true;

    if (plugin.api.on_load != nullptr) {
        if (!safe_call_on_load(plugin.api.on_load, &host_api_)) {
            close_plugin(plugin);
            return false;
        }
    }

    {
        std::lock_guard<std::mutex> guard(lock_);
        plugins_.push_back(std::move(plugin));
    }
    return true;
}

void plugin_manager::close_plugin(plugin_entry& plugin) {
    if (!plugin.loaded) {
        return;
    }

    if (plugin.api.on_unload != nullptr) {
        safe_call_on_unload(plugin.api.on_unload);
    }

    if (plugin.module != nullptr) {
        safe_free_library(plugin.module);
        plugin.module = nullptr;
    }

    plugin.loaded = false;
}

void plugin_manager::unload_all() {
    std::vector<plugin_entry> plugins{};
    std::unordered_map<std::uint64_t, patch_binding> host_patch_map{};
    std::unique_ptr<patcher_entry> self_patcher{};
    {
        std::lock_guard<std::mutex> guard(lock_);
        plugins.swap(plugins_);
        host_patch_map.swap(host_patch_map_);
        self_patcher.swap(self_patcher_);
    }

    for (plugin_entry& plugin : plugins) {
        close_plugin(plugin);
    }
}

void plugin_manager::on_process_start(std::uint32_t pid, const std::wstring& image_path) {
    std::vector<dbi_plugin_api> apis{};
    {
        std::lock_guard<std::mutex> guard(lock_);
        apis.reserve(plugins_.size());
        for (const plugin_entry& plugin : plugins_) {
            if (plugin.loaded && plugin.api.on_process_start != nullptr) {
                apis.push_back(plugin.api);
            }
        }
    }

    const std::string utf8 = wide_to_utf8(image_path);
    const char* path_ptr = utf8.empty() ? nullptr : utf8.c_str();
    for (const dbi_plugin_api& api : apis) {
        safe_call_on_process_start(api.on_process_start, pid, path_ptr);
    }
}

void plugin_manager::on_process_exit(std::uint32_t pid, std::uint32_t exit_code) {
    std::vector<dbi_plugin_api> apis{};
    {
        std::lock_guard<std::mutex> guard(lock_);
        apis.reserve(plugins_.size());
        for (const plugin_entry& plugin : plugins_) {
            if (plugin.loaded && plugin.api.on_process_exit != nullptr) {
                apis.push_back(plugin.api);
            }
        }
    }

    for (const dbi_plugin_api& api : apis) {
        safe_call_on_process_exit(api.on_process_exit, pid, exit_code);
    }
}

void plugin_manager::on_instruction_hit(std::uint32_t pid, std::uint64_t address) {
    std::vector<dbi_plugin_api> apis{};
    {
        std::lock_guard<std::mutex> guard(lock_);
        apis.reserve(plugins_.size());
        for (const plugin_entry& plugin : plugins_) {
            if (plugin.loaded && plugin.api.on_instruction_hit != nullptr) {
                apis.push_back(plugin.api);
            }
        }
    }

    for (const dbi_plugin_api& api : apis) {
        safe_call_on_instruction_hit(api.on_instruction_hit, pid, address);
    }
}

void plugin_manager::on_branch_hit(std::uint32_t pid, std::uint64_t address, const char* mnemonic, std::uint8_t length) {
    std::vector<dbi_plugin_api> apis{};
    {
        std::lock_guard<std::mutex> guard(lock_);
        apis.reserve(plugins_.size());
        for (const plugin_entry& plugin : plugins_) {
            if (plugin.loaded && plugin.api.version >= 3u && plugin.api.on_branch_hit != nullptr) {
                apis.push_back(plugin.api);
            }
        }
    }

    for (const dbi_plugin_api& api : apis) {
        safe_call_on_branch_hit(api.on_branch_hit, pid, address, mnemonic, length);
    }
}

std::vector<plugin_manager::plugin_info> plugin_manager::list_loaded_plugins() const {
    std::lock_guard<std::mutex> guard(lock_);

    std::vector<plugin_info> infos{};
    infos.reserve(plugins_.size());
    for (const plugin_entry& plugin : plugins_) {
        if (!plugin.loaded) {
            continue;
        }

        plugin_info info{};
        info.api_version = plugin.api.version;
        info.name = plugin.api.name ? plugin.api.name : "";
        info.plugin_version = plugin.api.plugin_version ? plugin.api.plugin_version : "";
        info.description = plugin.api.description ? plugin.api.description : "";
        info.author = plugin.api.author ? plugin.api.author : "";
        info.options_json = (plugin.api.version >= 4u && plugin.api.options_json != nullptr) ? plugin.api.options_json : "";
        info.path = plugin.path;
        infos.push_back(std::move(info));
    }
    return infos;
}

bool plugin_manager::dispatch_command(const std::string& command, const std::vector<std::string>& args, int& out_exit_code) {
    out_exit_code = 1;

    std::vector<dbi_plugin_api> apis{};
    {
        std::lock_guard<std::mutex> guard(lock_);
        apis.reserve(plugins_.size());
        for (const plugin_entry& plugin : plugins_) {
            if (plugin.loaded && plugin.api.on_command != nullptr) {
                apis.push_back(plugin.api);
            }
        }
    }

    std::vector<const char*> argv{};
    argv.reserve(args.size());
    for (const std::string& s : args) {
        argv.push_back(s.c_str());
    }

    for (const dbi_plugin_api& api : apis) {
        int exit_code = 0;
        const int handled = safe_call_on_command(api.on_command, command.c_str(), static_cast<int>(argv.size()), argv.empty() ? nullptr : argv.data(), &exit_code);
        if (handled) {
            out_exit_code = exit_code;
            return true;
        }
    }

    return false;
}

bool plugin_manager::configure_loaded_plugins(const std::vector<std::string>& args) {
    std::vector<dbi_plugin_api> apis{};
    {
        std::lock_guard<std::mutex> guard(lock_);
        apis.reserve(plugins_.size());
        for (const plugin_entry& plugin : plugins_) {
            if (plugin.loaded && plugin.api.version >= 4u && plugin.api.on_configure != nullptr) {
                apis.push_back(plugin.api);
            }
        }
    }

    std::vector<const char*> argv{};
    argv.reserve(args.size());
    for (const std::string& s : args) {
        argv.push_back(s.c_str());
    }

    for (const dbi_plugin_api& api : apis) {
        if (!safe_call_on_configure(api.on_configure, static_cast<int>(argv.size()), argv.empty() ? nullptr : argv.data())) {
            return false;
        }
    }

    return true;
}

bool plugin_manager::apply_patch_bytes(
    std::uint32_t pid,
    std::uint64_t address,
    const std::uint8_t* bytes,
    std::size_t size,
    std::uint64_t& out_patch_id) {

    // Intentionally restrict plugin patching to the current process.
    if (pid == 0 || pid != GetCurrentProcessId() || address == 0 || bytes == nullptr || size == 0) {
        return false;
    }

    std::lock_guard<std::mutex> guard(lock_);

    if (!self_patcher_) {
        self_patcher_ = std::make_unique<patcher_entry>();
        self_patcher_->patcher = std::make_unique<live_patch_framework>();
        if (!self_patcher_->patcher->use_current_process()) {
            self_patcher_.reset();
            return false;
        }
    }

    std::vector<std::uint8_t> patch_bytes(bytes, bytes + size);
    std::uint64_t local_id = 0;
    if (!self_patcher_->patcher->write_patch(static_cast<std::uintptr_t>(address), patch_bytes, local_id)) {
        return false;
    }

    const std::uint64_t host_id = next_host_patch_id_++;
    host_patch_map_[host_id] = patch_binding{local_id};
    out_patch_id = host_id;
    return true;
}

bool plugin_manager::remove_patch(std::uint64_t patch_id) {
    std::lock_guard<std::mutex> guard(lock_);

    const auto it = host_patch_map_.find(patch_id);
    if (it == host_patch_map_.end()) {
        return false;
    }

    if (!self_patcher_) {
        host_patch_map_.erase(it);
        return false;
    }

    const patch_binding binding = it->second;
    const bool removed = self_patcher_->patcher->remove_patch(binding.local_patch_id);
    host_patch_map_.erase(it);

    if (self_patcher_->patcher->list_patches().empty()) {
        self_patcher_.reset();
    }

    return removed;
}
