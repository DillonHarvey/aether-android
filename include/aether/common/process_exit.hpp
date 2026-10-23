#pragma once
#include <cstdint>
#include <memory>
#include <optional>
namespace aether {
// Trusted host control flow, deliberately not a Java or std::exception failure.
struct ProcessExit final {std::uint8_t status;std::uint8_t signal=0;};
class ProcessState final {
  public:
    void request_exit(std::uint32_t value) noexcept {if(!exit_)exit_=static_cast<std::uint8_t>(value);}
    // Internal status is 128+signal; the cause remains distinct from an ordinary exit.
    void request_signal(std::uint8_t signal) noexcept {if(!exit_){exit_=static_cast<std::uint8_t>(128U+signal);signal_=signal;}}
    std::optional<std::uint8_t> exit_status() const noexcept {return exit_;}
    std::optional<std::uint8_t> termination_signal() const noexcept {return signal_;}
    void checkpoint() const {if(exit_)throw ProcessExit{*exit_,signal_.value_or(0)};}
  private:
    std::optional<std::uint8_t> exit_,signal_;
};
}
