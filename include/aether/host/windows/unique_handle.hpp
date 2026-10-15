#pragma once
#include <Windows.h>
#include <utility>

namespace aether::host {
// Owns kernel handles closed by CloseHandle; not HKEY/HMODULE/GDI objects.
class UniqueHandle {
  public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE value) noexcept : value_(value) {}
    ~UniqueHandle() { reset(); }
    UniqueHandle(const UniqueHandle &) = delete;
    UniqueHandle &operator=(const UniqueHandle &) = delete;
    UniqueHandle(UniqueHandle &&other) noexcept : value_(other.release()) {}
    UniqueHandle &operator=(UniqueHandle &&other) noexcept {
        if (this != &other)
            reset(other.release());
        return *this;
    }
    HANDLE get() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ != nullptr && value_ != INVALID_HANDLE_VALUE; }
    HANDLE release() noexcept { return std::exchange(value_, nullptr); }
    void reset(HANDLE value = nullptr) noexcept {
        if (value_ == value)
            return;
        if (*this)
            CloseHandle(value_);
        value_ = value;
    }

  private:
    HANDLE value_ = nullptr;
};
} // namespace aether::host
