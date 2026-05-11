#pragma once

#include <cstdint>

namespace dbi_ipc {
inline constexpr std::uint32_t message_magic = 0x50494244u; // "DBIP"
inline constexpr std::uint16_t protocol_version = 1u;

enum class message_type : std::uint16_t {
    hello = 1,
    start_instrument = 2,
    ack = 3
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

struct ack_payload {
    std::uint32_t status_code{0};
    char message[160]{};
};
} // namespace dbi_ipc

