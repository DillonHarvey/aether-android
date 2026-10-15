#pragma once
#include "aether/apk/inspect.hpp"
#include <memory>

namespace aether::apk {
// Incremental SHA-256 for bounded archive streams. No partial digest is published.
class Sha256 {
  public:
    Sha256();
    ~Sha256();
    Sha256(const Sha256 &) = delete;
    Sha256 &operator=(const Sha256 &) = delete;
    void update(Bytes bytes);
    std::string finish();

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::apk
