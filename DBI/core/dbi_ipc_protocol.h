#pragma once

#include <cstddef>
#include <cstdint>

namespace dbi_ipc {
inline constexpr std::uint32_t message_magic = 0x50494244u; // "DBIP"
inline constexpr std::uint16_t protocol_version = 1u;

enum class message_type : std::uint16_t {
    hello = 1,
    start_instrument = 2,
    ack = 3,
    start_instrument_v2 = 4
};

enum class instruction_backend : std::uint32_t {
    translated_cache = 0,
    cooperative_translation = 1,
    inline_hook = 2,
    dispatcher_code_cache = 3,
    guard_page_translation = 4
};

struct message_header {
    std::uint32_t magic{message_magic};
    std::uint16_t version{protocol_version};
    std::uint16_t type{0};
    std::uint32_t payload_size{0};
};

struct hello_payload {
    std::uint32_t pid{0};
    std::uint32_t plugin_api_version{0};
    std::uint32_t core_version_major{0};
    std::uint32_t core_version_minor{0};
    std::uint32_t core_version_patch{0};
};

struct start_instrument_payload {
    wchar_t module_name[128]{};
    wchar_t section_name[32]{};
};

inline constexpr std::size_t max_instrument_targets = 8;

struct start_instrument_v2_payload {
    wchar_t module_name[128]{};
    std::uint32_t backend{static_cast<std::uint32_t>(instruction_backend::guard_page_translation)};
    std::uint32_t target_count{0};
    std::uint64_t target_rvas[max_instrument_targets]{};
};

struct ack_payload {
    std::uint32_t status_code{0};
    char message[160]{};
};
} // namespace dbi_ipc

