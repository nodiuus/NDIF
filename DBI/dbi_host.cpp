#include "dbi_host.h"

#include <Windows.h>

std::wstring dbi_host::default_plugins_dir() {
    wchar_t path[MAX_PATH]{};
    const DWORD len = GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring exe_path(path, path + len);
    const std::size_t last_sep = exe_path.find_last_of(L"\\/");
    const std::wstring exe_dir = (last_sep == std::wstring::npos) ? L"." : exe_path.substr(0, last_sep);
    return exe_dir + L"\\plugins";
}

bool dbi_host::load_plugins(const std::wstring& plugins_dir, const std::vector<std::wstring>& explicit_plugins) {
    plugins_.load_from_directory(plugins_dir);
    for (const std::wstring& path : explicit_plugins) {
        plugins_.load_plugin(path);
    }
    return true;
}

plugin_manager& dbi_host::plugins() {
    return plugins_;
}

const plugin_manager& dbi_host::plugins() const {
    return plugins_;
}
