#pragma once

#include "plugin_manager.h"

#include <string>
#include <vector>

// Small "core host" wrapper: owns the plugin manager and provides a default plugin discovery location.
class dbi_host {
public:
    dbi_host() = default;
    ~dbi_host() = default;

    dbi_host(const dbi_host&) = delete;
    dbi_host& operator=(const dbi_host&) = delete;

    static std::wstring default_plugins_dir();

    bool load_plugins(const std::wstring& plugins_dir, const std::vector<std::wstring>& explicit_plugins);

    plugin_manager& plugins();
    const plugin_manager& plugins() const;

private:
    plugin_manager plugins_{};
};

