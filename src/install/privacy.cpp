#include "aether/install/privacy.hpp"
#include "aether/common/text.hpp"
#include "aether/privacy_content.hpp"

namespace aether::install {
std::string_view privacy_text() { return embedded::privacy_text; }
std::string privacy_json() {
    return "{\"schemaVersion\":1,\"operation\":\"privacy\",\"sourceSha256\":" +
           json_quote(embedded::privacy_sha256) + ",\"text\":" + json_quote(privacy_text()) + '}';
}
} // namespace aether::install
