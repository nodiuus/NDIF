#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

struct live_patch_record {
    std::uint64_t id{0};
    std::uintptr_t address{0};
    std::vector<std::uint8_t> original_bytes{};
    std::vector<std::uint8_t> patched_bytes{};
    std::uintptr_t trampoline_address{0};
    std::size_t trampoline_size{0};
    bool enabled{false};
};

class live_patch_framework {
public:
    live_patch_framework() = default;
    ~live_patch_framework();

    live_patch_framework(const live_patch_framework&) = delete;
    live_patch_framework& operator=(const live_patch_framework&) = delete;

    bool use_current_process();
    bool attach(DWORD pid);
    void detach();

    bool is_attached() const;
    DWORD target_pid() const;

    bool write_patch(std::uintptr_t address, const std::vector<std::uint8_t>& bytes, std::uint64_t& patch_id);
    bool write_nop_patch(std::uintptr_t address, std::size_t count, std::uint64_t& patch_id);
    bool write_int3_patch(std::uintptr_t address, std::size_t count, std::uint64_t& patch_id);
    // Replaces a whole-instruction prefix with a jump to destination. Unlike
    // write_detour_patch, no trampoline is emitted and overwritten instructions
    // are not replayed. This is intended for callers that already own a
    // translated/replacement destination.
    bool write_jump_patch(std::uintptr_t address, std::uintptr_t destination, std::uint64_t& patch_id);
    bool write_detour_patch(std::uintptr_t address, const std::vector<std::uint8_t>& injected_instructions, std::uint64_t& patch_id);

    bool remove_patch(std::uint64_t patch_id);
    void remove_all_patches();

    std::vector<live_patch_record> list_patches() const;

private:
    bool write_protected(std::uintptr_t address, const std::uint8_t* bytes, std::size_t size) const;
    bool read_bytes(std::uintptr_t address, std::size_t size, std::vector<std::uint8_t>& out_bytes) const;
    bool build_jump(std::uintptr_t src, std::uintptr_t dst, std::vector<std::uint8_t>& jump_bytes) const;
    bool decode_span(std::uintptr_t address, std::size_t min_size, std::size_t& span_size, std::vector<std::uint8_t>& span_bytes) const;
    bool decode_safe_span(std::uintptr_t address, std::size_t min_size, std::size_t& span_size, std::vector<std::uint8_t>& span_bytes) const;
    bool suspend_target_threads(std::vector<HANDLE>& suspended_handles) const;
    void resume_target_threads(std::vector<HANDLE>& suspended_handles) const;

    bool write_patch_internal(std::uintptr_t address, const std::vector<std::uint8_t>& bytes, live_patch_record& record);

    HANDLE process_handle_{nullptr};
    DWORD target_pid_{0};
    bool attached_to_remote_{false};
    std::uint64_t next_patch_id_{1};
    std::unordered_map<std::uint64_t, live_patch_record> patches_{};
    mutable std::mutex lock_{};
};
