#pragma once

#include <Windows.h>

#include <Zydis/Zydis.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <vector>

struct instrumented_instruction {
    std::uintptr_t address{};
    std::uint8_t length{};
    std::uint8_t original_first_byte{};
    bool is_control_flow{false};
    ZydisMnemonic mnemonic{ZYDIS_MNEMONIC_INVALID};
};

class dynamic_binary_instrumentor {
public:
    using callback_type = std::function<void(const instrumented_instruction&, CONTEXT&)>;

    dynamic_binary_instrumentor() = default;
    ~dynamic_binary_instrumentor();

    dynamic_binary_instrumentor(const dynamic_binary_instrumentor&) = delete;
    dynamic_binary_instrumentor& operator=(const dynamic_binary_instrumentor&) = delete;

    bool add_region(void* start, std::size_t size);
    bool install(callback_type callback);
    void uninstall();

private:
    struct address_range {
        std::uintptr_t start{};
        std::size_t size{};
    };

    static LONG CALLBACK vectored_handler(PEXCEPTION_POINTERS exception_info);

    bool decode_region(const address_range& range);
    bool write_byte(std::uintptr_t address, std::uint8_t value) const;
    const instrumented_instruction* find_instruction(std::uintptr_t address) const;

    static std::uintptr_t get_instruction_pointer(const CONTEXT& context);
    static void set_instruction_pointer(CONTEXT& context, std::uintptr_t value);
    static void set_single_step(CONTEXT& context);

    std::vector<address_range> ranges_{};
    std::unordered_map<std::uintptr_t, instrumented_instruction> instructions_{};
    callback_type callback_{};
    void* veh_handle_{nullptr};
    mutable std::mutex lock_{};

    static dynamic_binary_instrumentor* active_instance_;
    static thread_local bool has_pending_rearm_;
    static thread_local std::uintptr_t pending_rearm_address_;
};
