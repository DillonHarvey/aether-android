#pragma once
#include <cstdint>
#include <memory>
#include <optional>
namespace aether {
// Trusted host control flow, deliberately not a Java or std::exception failure.
struct ProcessExit final {std::uint8_t status;};
class ProcessState final {
  public:
    void request_exit(std::uint32_t value) noexcept {if(!exit_)exit_=static_cast<std::uint8_t>(value);}
    std::optional<std::uint8_t> exit_status() const noexcept {return exit_;}
    void checkpoint() const {if(exit_)throw ProcessExit{*exit_};}
  private:
    std::optional<std::uint8_t> exit_;
};
}
