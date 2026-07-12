#pragma once

#include <Windows.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

enum class staged_agent_phase {
    idle,
    process_launched,
    waiting_for_initialization,
    controller_ready,
    agent_injected,
    agent_connected,
    instrumentation_started,
    completed,
    failed
};

struct staged_agent_event {
    staged_agent_phase phase{staged_agent_phase::idle};
    DWORD pid{0};
    std::string message{};
};

struct staged_agent_options {
    using event_callback = std::function<void(const staged_agent_event&)>;

    std::wstring executable_path{};
    std::vector<std::wstring> arguments{};
    std::wstring agent_dll_path{};

    // Passed to the in-target agent after the handshake.
    std::wstring module_name{};
    std::wstring section_name{};

    // The process is launched normally (without DEBUG_PROCESS). NDIF waits for
    // the main module to become observable and then gives the loader this
    // additional quiet period before injecting the cooperative agent.
    DWORD initialization_timeout_ms{15000};
    DWORD settle_time_ms{1500};
    DWORD pipe_timeout_ms{7500};

    event_callback on_event{};
};

struct staged_agent_result {
    DWORD pid{0};
    staged_agent_phase final_phase{staged_agent_phase::idle};
    std::uint32_t agent_status{0};
    std::string agent_message{};
    DWORD win32_error{ERROR_SUCCESS};
};

// Cooperative post-initialization backend. It deliberately avoids the Windows
// debugging APIs: launch normally, wait for initialization, inject dbi_agent,
// complete the versioned pipe handshake, then ask the agent to start.
class staged_agent_backend {
public:
    bool run(const staged_agent_options& options, staged_agent_result& result);

private:
    static std::wstring quote_argument(const std::wstring& value);
    static std::wstring build_command_line(
        const std::wstring& executable_path,
        const std::vector<std::wstring>& arguments);
};
