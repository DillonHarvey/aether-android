#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
namespace aether {
// Trusted host control flow, deliberately not a Java or std::exception failure.
struct ProcessExit final {
    std::uint8_t status;
    std::uint8_t signal=0;
    std::shared_ptr<const std::string> abort_message{};
};
class ProcessState final {
  public:
    void request_exit(std::uint32_t value) noexcept {if(!exit_)exit_=static_cast<std::uint8_t>(value);}
    // Internal status is 128+signal; the cause remains distinct from an ordinary exit.
    void request_signal(std::uint8_t signal) noexcept {if(!exit_){exit_=static_cast<std::uint8_t>(128U+signal);signal_=signal;}}
    std::optional<std::uint8_t> exit_status() const noexcept {return exit_;}
    std::optional<std::uint8_t> termination_signal() const noexcept {return signal_;}
    std::shared_ptr<const std::string> abort_message() const noexcept {return abort_message_;}
    // Same single-owner discipline as the terminal cause. An engaged empty
    // string is a claimed message; construct completely before publishing it.
    void set_abort_message(std::string value) {
        if(abort_message_)return;
        auto message=std::make_shared<const std::string>(std::move(value));
        abort_message_=std::move(message);
    }
    // Copy immutable ownership through unwind without allocating on this path.
    void checkpoint() const {if(exit_)throw ProcessExit{*exit_,signal_.value_or(0),abort_message_};}
  private:
    std::optional<std::uint8_t> exit_,signal_;
    std::shared_ptr<const std::string> abort_message_;
};
}
