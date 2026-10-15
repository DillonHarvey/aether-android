#pragma once
#include "aether/apk/inspect.hpp"
#include "aether/common/text.hpp"
#include <charconv>
#include <map>

namespace aether::apk::metadata {
class JsonError : public std::runtime_error {
  public:
    bool limited;
    JsonError(std::string text, bool is_limit = false)
        : std::runtime_error(std::move(text)), limited(is_limit) {}
};
[[noreturn]] inline void bad(std::string message) { throw JsonError(std::move(message)); }
[[noreturn]] inline void limit(std::string message) { throw JsonError(std::move(message), true); }
struct Json {
    enum class Kind { object, array, string, number, literal } kind;
    std::string scalar;
    std::map<std::string, Json> object;
    std::vector<Json> array;
    const Json &get(const std::string &key) const {
        const auto found = object.find(key);
        if (kind != Kind::object || found == object.end())
            bad("Package index is missing field: " + key);
        return found->second;
    }
    const Json *find(const std::string &key) const {
        const auto it = object.find(key);
        return kind == Kind::object && it != object.end() ? &it->second : nullptr;
    }
    std::string string() const {
        if (kind != Kind::string)
            bad("Package index field must be a string");
        return scalar;
    }
    std::uint64_t wide_integer(bool allow_string = false) const {
        if (kind != Kind::number && !(allow_string && kind == Kind::string))
            bad("Package index field must be an unsigned integer");
        std::uint64_t value = 0;
        const auto parsed = std::from_chars(scalar.data(), scalar.data() + scalar.size(), value);
        if (scalar.empty() || (scalar.size() > 1 && scalar.front() == '0') || parsed.ec != std::errc{} ||
            parsed.ptr != scalar.data() + scalar.size())
            bad("Package index integer is outside the canonical uint64 range");
        return value;
    }
    std::uint32_t integer(bool allow_string = false) const {
        const auto result = wide_integer(allow_string);
        if (result > UINT32_MAX)
            bad("Package index integer is outside the canonical uint32 range");
        return static_cast<std::uint32_t>(result);
    }
};
// Original bounded JSON reader for the untrusted vendor index. Unknown fields
// are parsed completely, including duplicate keys/UTF validation; they confer
// no authority. No external JSON implementation or platform parser is imported.
class JsonReader {
  public:
    explicit JsonReader(Bytes bytes) : input_(reinterpret_cast<const char *>(bytes.data()), bytes.size()) {
        if (bytes.size() > 1024 * 1024)
            limit("Package JSON exceeds 1 MiB");
        try {
            (void)utf16(input_);
        } catch (const std::invalid_argument &) {
            bad("Package index is not valid UTF-8");
        }
    }
    Json read() {
        auto result = value(0);
        space();
        if (position_ != input_.size())
            bad("Trailing data after Package JSON index");
        return result;
    }

  private:
    std::string_view input_;
    std::size_t position_ = 0, nodes_ = 0;
    void space() {
        while (position_ < input_.size() && (input_[position_] == ' ' || input_[position_] == '\n' ||
                                             input_[position_] == '\r' || input_[position_] == '\t'))
            ++position_;
    }
    bool take(char c) {
        space();
        if (position_ < input_.size() && input_[position_] == c) {
            ++position_;
            return true;
        }
        return false;
    }
    void expect(char c) {
        if (!take(c))
            bad("Invalid Package JSON syntax");
    }
    std::uint16_t hex() {
        if (input_.size() - position_ < 4)
            bad("Truncated JSON Unicode escape");
        std::uint16_t result = 0;
        for (unsigned i = 0; i < 4; ++i) {
            const auto c = input_[position_++];
            const int digit = c >= '0' && c <= '9'   ? c - '0'
                              : c >= 'a' && c <= 'f' ? c - 'a' + 10
                              : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                                     : -1;
            if (digit < 0)
                bad("Invalid JSON Unicode escape");
            result = static_cast<std::uint16_t>(result * 16 + digit);
        }
        return result;
    }
    std::string string() {
        expect('"');
        std::string result;
        while (position_ < input_.size()) {
            const auto c = static_cast<unsigned char>(input_[position_++]);
            if (c == '"')
                return result;
            if (c < 0x20)
                bad("Unescaped control character in JSON string");
            if (c != '\\') {
                result += static_cast<char>(c);
            } else {
                if (position_ == input_.size())
                    bad("Truncated JSON escape");
                switch (input_[position_++]) {
                case '"':
                    result += '"';
                    break;
                case '\\':
                    result += '\\';
                    break;
                case '/':
                    result += '/';
                    break;
                case 'b':
                    result += '\b';
                    break;
                case 'f':
                    result += '\f';
                    break;
                case 'n':
                    result += '\n';
                    break;
                case 'r':
                    result += '\r';
                    break;
                case 't':
                    result += '\t';
                    break;
                case 'u': {
                    const auto first = hex();
                    std::wstring wide(1, static_cast<wchar_t>(first));
                    if (first >= 0xd800 && first <= 0xdbff) {
                        if (input_.substr(position_, 2) != "\\u")
                            bad("Unpaired JSON high surrogate");
                        position_ += 2;
                        const auto second = hex();
                        if (second < 0xdc00 || second > 0xdfff)
                            bad("Unpaired JSON high surrogate");
                        wide += static_cast<wchar_t>(second);
                    } else if (first >= 0xdc00 && first <= 0xdfff) {
                        bad("Unpaired JSON low surrogate");
                    }
                    result += utf8(wide);
                    break;
                }
                default:
                    bad("Unknown JSON escape");
                }
            }
            if (result.size() > 64 * 1024)
                limit("Package index string exceeds 64 KiB");
        }
        bad("Unterminated JSON string");
    }
    Json value(std::size_t depth) {
        if (depth > 16 || ++nodes_ > 16384)
            limit("Package JSON exceeds 16 nesting levels or 16384 values");
        space();
        if (position_ == input_.size())
            bad("Truncated Package JSON value");
        if (input_[position_] == '"')
            return {Json::Kind::string, string(), {}, {}};
        if (take('{')) {
            Json result{Json::Kind::object, {}, {}, {}};
            if (take('}'))
                return result;
            do {
                auto key = string();
                expect(':');
                auto child = value(depth + 1);
                if (!result.object.emplace(std::move(key), std::move(child)).second)
                    bad("Duplicate JSON object key");
            } while (take(','));
            expect('}');
            return result;
        }
        if (take('[')) {
            Json result{Json::Kind::array, {}, {}, {}};
            if (take(']'))
                return result;
            do {
                result.array.push_back(value(depth + 1));
            } while (take(','));
            expect(']');
            return result;
        }
        for (const auto literal :
             {std::string_view("true"), std::string_view("false"), std::string_view("null")}) {
            if (input_.substr(position_, literal.size()) == literal) {
                position_ += literal.size();
                return {Json::Kind::literal, std::string(literal), {}, {}};
            }
        }
        const auto start = position_;
        if (input_[position_] == '-')
            ++position_;
        const auto digit = [&] {
            return position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9';
        };
        if (!digit())
            bad("Invalid JSON value");
        if (input_[position_++] != '0')
            while (digit())
                ++position_;
        if (position_ < input_.size() && input_[position_] == '.') {
            ++position_;
            if (!digit())
                bad("Invalid JSON fraction");
            while (digit())
                ++position_;
        }
        if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
            ++position_;
            if (position_ < input_.size() && (input_[position_] == '+' || input_[position_] == '-'))
                ++position_;
            if (!digit())
                bad("Invalid JSON exponent");
            while (digit())
                ++position_;
        }
        return {Json::Kind::number, std::string(input_.substr(start, position_ - start)), {}, {}};
    }
};
} // namespace aether::apk::metadata
