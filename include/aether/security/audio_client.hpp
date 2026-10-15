#pragma once
#include "aether/host/audio_stream.hpp"
#include "aether/security/client.hpp"

namespace aether::security {
// Streams retain their client by reference; the channel must outlive them.
class BrokerAudioService final : public host::AudioService {
  public:
    explicit BrokerAudioService(BrokerClient &client) : client_(client) {}
    std::unique_ptr<host::AudioStream> open(host::AudioConfig config) override;

  private:
    BrokerClient &client_;
};
} // namespace aether::security
