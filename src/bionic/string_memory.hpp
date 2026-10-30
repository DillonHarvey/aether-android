#pragma once
#include "aether/a64/guest_cpu.hpp"

namespace aether::bionic {
enum class StringMemoryOperation {
    compare, compare_n, copy_n, find_char, find_last_char, find_text,
    compare_bytes, find_byte, find_bytes, checked_length, checked_find_char,
    checked_find_last_char, checked_copy_n, checked_copy_n_source, checked_move, copy_sized, tokenize, tokenize_reentrant, checked_copy, checked_copy_end, checked_fill, length_n,
    copy_end, concatenate_n, span_accept, span_reject, find_any
};

// Original guest-memory implementation. No guest pointer is a host pointer.
// Scans and transfers are limited to 1 MiB; larger work faults explicitly.
class NativeStringMemory {
  public:
    explicit NativeStringMemory(a64::GuestMemory &memory) : memory_(memory) {}
    a64::Fault invoke(StringMemoryOperation, std::array<std::uint64_t, 31> &) noexcept;
    std::string_view rejection() const noexcept { return rejection_; }
  private:
    a64::GuestMemory &memory_;
    std::string_view rejection_;
    a64::Address token_next_=0; // Bionic strtok state is process-shared, not thread-local.
};
} // namespace aether::bionic
